FROM registry.suse.com/bci/gcc:15
RUN zypper --non-interactive in automake automake libtool diffutils
RUN zypper --non-interactive in git liburing-devel libuuid-devel
ENV UBLKSRC /usr/src/ublksrv

WORKDIR $UBLKSRC
ADD . $UBLKSRC
RUN autoreconf -i
RUN ./configure
RUN make
