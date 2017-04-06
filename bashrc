#combine key for easy use
alias ll='ls -al'
alias ls='ls --color=auto'
alias f='find . -iname'
alias du='du -sh *'
alias df='df -h'

export PS1="\[\e]0;\w\a\]\n\[\e[31m\]\u:\[\e[33m\]\W\[\e[0m\]\$ "
PS1='${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u:\[\033[01;33m\]\W\[\033[00m\]\$ '
if [ "$color_prompt" = yes ]; then
     PS1='${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u:\[\033[01;33m\]\W\[\033[00m\]\$ '
     #PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u:\W\$ '
fi

#export PATH for bin file
export PATH="/home/xerox_lin/script:$PATH"
export PATH="/home/xerox_lin/android/platform-tools:$PATH"
export PATH="/home/xerox_lin/crosscompiler/aarch64-linux-android-4.9/bin:$PATH"
export PATH="/home/xerox_lin/crosscompiler/arm-eabi-4.8/bin:$PATH"
