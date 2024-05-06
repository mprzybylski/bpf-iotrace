FROM gentoo/stage3:20240422

RUN emerge --sync
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" \
        emerge sys-devel/crossdev app-eselect/eselect-repository dev-vcs/git
RUN eselect repository add rescued-ebuilds git https://github.com/mprzybylski/rescued-ebuilds.git && \
    emerge --sync
RUN eselect repository create crossdev

RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" \
        crossdev --target x86_64-generic-linux-gnu --gcc "=13.2.1_p20240426" --libc "=2.27-r3" \
        -ol rescued-ebuilds --kernel "=4.14-r2" --ex-gdb --portage --verbose

RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge dev-build/cmake dev-build/ninja
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge sys-devel/clang

# vcpkg bootstrap prerequisites
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge net-misc/curl app-arch/zip \
        app-arch/unzip app-arch/tar

RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge dev-util/bpftool

# Unprivilged user to make UID/GID mapping easier
ARG USERNAME
ARG USER_UID
RUN FEATURES="-ipc-sandbox -network-sandbox -pid-sandbox" emerge app-admin/sudo && \
    echo "CREATE_MAIL_SPOOL=no" >> /etc/default/useradd && \
    useradd -U $USERNAME --uid $USER_UID  && \
    mkdir -m 0770 /etc/sudoers.d && \
    echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME