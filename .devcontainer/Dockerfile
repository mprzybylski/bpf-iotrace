FROM gentoo/stage3:20240506

RUN emerge --sync
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" \
        emerge sys-devel/crossdev app-eselect/eselect-repository dev-vcs/git
RUN eselect repository add rescued-ebuilds git https://github.com/mprzybylski/rescued-ebuilds.git && \
    emerge --sync rescued-ebuilds
RUN eselect repository create crossdev

RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" \
        crossdev --target x86_64-generic-linux-gnu --gcc '~14.1.0' \
        --libc '~2.26' -ol rescued-ebuilds --kernel '~4.14' --ex-gdb --portage --verbose

RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge dev-build/cmake dev-build/ninja

# vcpkg bootstrap prerequisites
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge net-misc/curl app-arch/zip \
        app-arch/unzip app-arch/tar

# Use gentoo's latest stable Clang and LLVM versions
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge 'sys-devel/clang' sys-devel/llvm

# bpftool depends on LLVM, so install it later
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge dev-util/bpftool

# Unprivilged user to make UID/GID mapping easier
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge app-admin/sudo
ARG USERNAME
ARG USER_UID
RUN echo "CREATE_MAIL_SPOOL=no" >> /etc/default/useradd && \
    useradd -U $USERNAME --uid $USER_UID  && \
    mkdir -m 0770 /etc/sudoers.d && \
    echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME