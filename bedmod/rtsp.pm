package bedmod::rtsp;

use strict;
use warnings;
#use diiagnostics;

use Socket;

# self package is an extension to bed, to check
# for http server vulnerabilities.

sub new{
    my $self = {
        healthy => '',
    };

    bless $self;
}

sub init{
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 554;

    return if $args{d};

    die "\nRTSP server failed health check!\n"
        unless $self->health_check();
}

sub health_check {
    my $self = shift;

    my $iaddr = inet_aton($self->{target})
        || die "\nUnknown host: $self->{target}\n";

    my $paddr = sockaddr_in($self->{port}, $iaddr)
        || die "\ngetprotobyname: $!\n";

    my $proto = getprotobyname('tcp')
        || die "\ngetprotobyname: $!\n";

    socket(SOCKET, PF_INET, SOCK_STREAM, $proto)
        || die "\nsocket: $!\n";

    connect(SOCKET, $paddr)
        || die "\nconnection attempt failed: $!\n";

    send(SOCKET, "DESCRIBE / RTSP/1.0\r\n\r\n", 0)
        || die "\nHTTP request failed: $!\n";

    my $resp = <SOCKET>;

    if (!$self->{healthy}) {
        $self->{healthy} = $resp if $resp =~ /RTSP/;
        # print "Set healthy: $resp";
    }
    #print "DBG: Health resp: $resp\n";
    return $resp =~ m/^$self->{healthy}$/;
}

sub getQuit{
    ("\r\n\r\n");
}

sub getLoginarray {
    (
        "XAXAX\r\n\r\n",
        "XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "XAXAX / RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "XAXAX rtsp://localhost/file.mpg\r\nCSeq: 1\r\n\r\n",
        "XAXAX rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "OPTIONS XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "OPTIONS /XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "OPTIONS * XAXAX\r\nCSeq: 1\r\n\r\n",
        "OPTIONS * RTSP/1.0\r\nXAXAX: 1\r\n\r\n",
        "OPTIONS * RTSP/1.0\r\nCSeq: XAXAX\r\n\r\n",
        "DESCRIBE XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://localhost/XAXAX=0 RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://localhost/trackID=XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://XAXAX\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://XAXAX:pass\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://user:XAXAX\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://XAXAX:XAXAX\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://localhost/file.mpg XAXAX\r\nCSeq: 1\r\n\r\n",
        "DESCRIBE rtsp://localhost/file.mpg RTSP/XAXAX\r\nCSeq: 1\r\n\r\n",
        "SETUP XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SETUP XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SETUP rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SETUP rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SETUP rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 7\r\nContent-length: 3200\r\n\r\nXAXAX\r\n\r\n",
        "PLAY XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://localhost/XAXAX=0 RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://localhost/trackID=XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://XAXAX\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://XAXAX:pass\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://user:XAXAX\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://XAXAX:XAXAX\@localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://localhost/file.mpg XAXAX\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://localhost/file.mpg RTSP/XAXAX\r\nCSeq: 1\r\n\r\n",
        "PLAY rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 7\r\nContent-length: 3200\r\n\r\nXAXAX\r\n\r\n",
        "PAUSE XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PAUSE XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PAUSE rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "PAUSE rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "RECORD XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "RECORD XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "RECORD rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "RECORD rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "ANNOUNCE XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "ANNOUNCE XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "ANNOUNCE rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "ANNOUNCE rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "TEARDOWN XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "TEARDOWN XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "TEARDOWN rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "TEARDOWN rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "GET_PARAMETER XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "GET_PARAMETER XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "GET_PARAMETER rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "GET_PARAMETER rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SET_PARAMETER XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SET_PARAMETER XAXAX://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SET_PARAMETER rtsp://XAXAX/file.mpg RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SET_PARAMETER rtsp://localhost/XAXAX RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "SET_PARAMETER rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nContent-type: text/parameters\r\n\r\nXAXAX: XAXAX\r\n",
    );
}

sub getCommandarray {
    (
        "XAXAX: XAXAX\r\n\r\n",
        "Accept: XAXAX\r\n\r\n",
        "Accept-Encoding: XAXAX\r\n\r\n",
        "Accept-Language: XAXAX\r\n\r\n",
        "Accept-Charset: XAXAX\r\n\r\n",
        "Authorization: XAXAX\r\n\r\n",
        "Authorization: XAXAX\r\n\r\n",
        "Authorization: Basic XAXAX\r\n\r\n",
        "Authorization XAXAX: Basic AAAAAA\r\n\r\n",
        "Authorization: XAXAX:foo\r\n\r\n",
        "Authorization: foo:XAXAX\r\n\r\n",
        "Content-length: XAXAX\r\n",
        "Content-type: XAXAX\r\n",
        "Content-Type: text/parameters\r\n\r\nXAXAX: XAXAX\r\n\r\n",
        "CSeq: XAXAX\r\n\r\n",
        "From: XAXAX\r\n\r\n",
        "If-Modified-Since: XAXAX\r\n\r\n",
        "Proxy-Require: XAXAX\r\n",
        "Range: XAXAX\r\n\r\n",
        "Range: clock=XAXAX-XAXAX\r\n\r\n",
        "Referer: XAXAX\r\n\r\n",
        "Require: XAXAX\r\n\r\n",
        "Transport: XAXAX\r\n\r\n",
        "Session: XAXAX\r\n\r\n",
        "User-Agent: XAXAX\r\n\r\n",
    );
}

sub getLogin{
    (
        "ANNOUNCE rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n",
        "DESCRIBE rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n",
        "DESCRIBE rtsp://localhost/file.mpg RTSP/1.0\r\n",
        "PLAY rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n",
        "PAUSE rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n",
        "SETUP rtsp://localhost/file.mpg RTSP/1.0\r\nCSeq: 1\r\n",
    );
}

sub testMisc {()}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
