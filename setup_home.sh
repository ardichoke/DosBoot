#!/bin/bash
hcdir="~/homeconfig"
date=$(date +%Y%m%d)
if [ -d ${hcdir} ]; then
    echo "Making symlinks..."
    for file in $(ls -A "${hcdir}"); do
        [[ "$file" == ".git" ]] && echo "Skipping $file" && continue
        [ -e "~/$file" ] && echo "Moving $file" && mv -fv ~/$file{,.${date}}
        echo "Linking $file"
        ln -sf "${hcdir}/${file}" "~/${file}"
    done

else
    echo "${hcdir} doesn't exist"
    exit 1
fi
git submodule init
git submodule update
