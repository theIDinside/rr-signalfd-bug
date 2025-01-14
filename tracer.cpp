#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#define EPOLL_EVENTS 1

#define LOG_LINE(PROC_ID, fmtString, ...)                                      \
  std::printf("[%d]: " fmtString "\n", PROC_ID __VA_OPT__(, ) __VA_ARGS__);

static bool KeepRunning = true;

static int Pipe[2];

struct WaitResult {
  pid_t pid;
  int status;
};

constexpr auto IsPtraceEvent(int stopstatus,
                             int ptrace_event) noexcept -> bool {
  return stopstatus >> 8 == (SIGTRAP | (ptrace_event << 8));
}

void LogWaitStatus(WaitResult wait) {
  if (WIFEXITED(wait.status)) {
    LOG_LINE(wait.pid, "Child exited with status %d\n",
             WEXITSTATUS(wait.status));
  } else if (WIFSIGNALED(wait.status)) {
    LOG_LINE(wait.pid, "Child killed by signal %d (%s)", WTERMSIG(wait.status),
             strsignal(WTERMSIG(wait.status)));
  } else if (WIFSTOPPED(wait.status)) {
    LOG_LINE(wait.pid, "Child stopped by signal %d (%s)", WSTOPSIG(wait.status),
             strsignal(WSTOPSIG(wait.status)));
    if (IsPtraceEvent(wait.status, PTRACE_EVENT_FORK)) {
      LOG_LINE(wait.pid, "PTRACE_EVENT_FORK");
    } else if (IsPtraceEvent(wait.status, PTRACE_EVENT_VFORK)) {
      LOG_LINE(wait.pid, "PTRACE_EVENT_VFORK");
    } else if (IsPtraceEvent(wait.status, PTRACE_EVENT_CLONE)) {
      pid_t new_child = 0;
      // interestingly, on my machine, unless I place waitedPid here, the call
      // to ptrace(PTRACE_GETEVENTMSG, ...) clobbers waitPid value lol :'D.
      // Gotta love ptrace. If you want a good laugh place `waitedPid =
      // wait.pid` at the very top of the function.
      auto waitedPid = wait.pid;
      auto result = ptrace(PTRACE_GETEVENTMSG, waitedPid, nullptr, &new_child);
      LOG_LINE(waitedPid, "PTRACE_EVENT_CLONE: new child %d", new_child);
    } else if (IsPtraceEvent(wait.status, PTRACE_EVENT_EXEC)) {
      LOG_LINE(wait.pid, "PTRACE_EVENT_EXEC");
    } else if (IsPtraceEvent(wait.status, PTRACE_EVENT_EXIT)) {
      LOG_LINE(wait.pid, "PTRACE_EVENT_EXIT");
    } else {
      LOG_LINE(wait.pid, "Unknown ptrace event");
    }
  } else {
    LOG_LINE(wait.pid, "Unknown wait status: 0x%x\n", wait.status);
  }
}

void UnblockSignals() {
  struct sigaction sa;
  sa.sa_handler = SIG_DFL; // Default action
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  for (int sig = 1; sig < NSIG; ++sig) {
    // Skip invalid signals
    if (sigaction(sig, &sa, NULL) == -1 && sig != SIGKILL && sig != SIGSTOP) {
      perror("sigaction");
    }
  }
}

void SetPtraceOptions(pid_t pid) {
  constexpr auto options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC |
                           PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD |
                           PTRACE_O_TRACEVFORK;
  if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) == -1) {
    printf("failed setoptions for %d: ", pid);
    perror("failed to set desired options");
    exit(-1);
  } else {
    printf("setoptions to trace clones as well\n");
  }
}

void WaitStatusReaderThread() {
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    _exit(EXIT_FAILURE);
  }
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  int sfd = signalfd(-1, &mask, 0);
  if (sfd == -1) {
    perror("signalfd");
    _exit(EXIT_FAILURE);
  }

  struct epoll_event ev, events[EPOLL_EVENTS];
  ev.events = EPOLLIN;
  ev.data.fd = sfd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev) == -1) {
    perror("epoll_ctl");
    _exit(EXIT_FAILURE);
  }

  bool init = false;

  while (KeepRunning) {
    int nfds = epoll_wait(epoll_fd, events, EPOLL_EVENTS, 5);
    if (nfds == -1) {
      if (errno == EINTR)
        continue;
      perror("epoll_wait");
      break;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == sfd) {
        struct signalfd_siginfo fdsi;
        ssize_t s = read(sfd, &fdsi, sizeof(fdsi));
        if (s != sizeof(fdsi)) {
          perror("read");
          continue;
        }

        if (fdsi.ssi_signo == SIGCHLD) {
          int status;
          pid_t pid;

          while ((pid = waitpid(-1, &status, __WALL | WNOHANG)) > 0) {

            WaitResult result{.pid = pid, .status = status};
            if (write(Pipe[1], &result, sizeof(result)) == -1) {
              perror("Failed to write wait event");
              _exit(EXIT_FAILURE);
            }
          }
        }
      }
    }
  }

  close(sfd);
  close(epoll_fd);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program_to_trace>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  if (pipe(Pipe) == -1) {
    perror("failed to open pipe");
    exit(EXIT_FAILURE);
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    perror("sigprocmask");
    return EXIT_FAILURE;
  }

  auto waitStatusThread = std::thread{WaitStatusReaderThread};

  pid_t child_pid = fork();
  if (child_pid == -1) {
    perror("fork");
    return EXIT_FAILURE;
  }

  if (child_pid == 0) { // Child process
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace");
      exit(EXIT_FAILURE);
    }
    execlp(argv[1], argv[1], NULL);
    perror("execlp");
    exit(EXIT_FAILURE);
  }

  // Parent process
  int expectedExits = 6;
  bool init = false;
  while (expectedExits > 0) {
    WaitResult waitResult;
    int readRes = 0;
    if (readRes = read(Pipe[0], &waitResult, sizeof(waitResult));
        readRes == -1 || readRes != sizeof(WaitResult)) {
      perror("Failed to read from pipe");
      exit(EXIT_FAILURE);
    }

    if (!init) {
      SetPtraceOptions(waitResult.pid);
      init = true;
    }

    LogWaitStatus(waitResult);

    if (WIFSTOPPED(waitResult.status)) {
      if (ptrace(PTRACE_CONT, waitResult.pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_CONT) failed: exiting");
        exit(-1);
      }
    } else if (WIFEXITED(waitResult.status)) {
      --expectedExits;
    }
  }
  printf("Exiting \n");
  KeepRunning = false;

  close(Pipe[0]);
  close(Pipe[1]);

  waitStatusThread.join();

  return EXIT_SUCCESS;
}
