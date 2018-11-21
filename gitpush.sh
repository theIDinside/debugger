#!/bin/bash
echo "Add commit message for submodule: "
read sc_msg
cd ./deps/command_prompt/
git add -A
git commit -m "$sc_msg"
git push origin master
cd ..
cd ..
echo "Add commit message for parent repo: "
read parent_repo_msg
git add -A
git add ./deps/command_prompt/
git commit -m "$parent_repo_msg"
git push origin master --recurse-submodules=on-demand


