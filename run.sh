#!/bin/bash
clang++ --std=c++20 -g3 -o tracer tracer.cpp
clang++ --std=c++20 -g3 -o child child.cpp

echo "this should execute and exit"
./tracer ./child
echo "exited successfully!"
sleep 2
echo "this will never exit..."
echo "running 'rr record ./tracer ./child'"
sleep 1
rr record ./tracer ./child