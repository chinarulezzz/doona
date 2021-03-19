package bedmod::proxy;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check for http proxy server
# vulnerabilities.

sub new {
    bless {};
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto}   = 'tcp';
    $self->{healthy} = '';
    $self->{port}    = $args{p} || 8080;

    return if $args{d};

    die "\nProxy server failed health check!\n"
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

    send(SOCKET, "HEAD / HTTP/1.0\r\n\r\n", 0)
        || die "\nHTTP request failed: $!\n";

    my $resp = <SOCKET>;

    if (!$self->{healthy}) {
        $self->{healthy} = $resp if $resp =~ /HTTP/;
        # print "Set healthy: $resp";
    }
    return $resp =~ m/$self->{healthy}/;
}

sub getQuit {
    ("\r\n\r\n");
}

sub getLoginarray {
    (
        "XAXAX\r\n\r\n",
        "XAXAX http://127.0.0.2/ HTTP/1.0\r\n\r\n",
        "HEAD http://XAXAX/ HTTP/1.0\r\n\r\n",
        "HEAD http://127.0.0.2:XAXAX/ HTTP/1.0\r\n\r\n",
        "HEAD http://127.0.0.2/XAXAX HTTP/1.0\r\n\r\n",
        "HEAD http://127.0.0.2/ XAXAX\r\n\r\n",
        "GET http://XAXAX/ HTTP/1.0\r\n\r\n",
        "GET http://127.0.0.2:XAXAX/ HTTP/1.0\r\n\r\n",
        "GET http://127.0.0.2/XAXAX HTTP/1.0\r\n\r\n",
        "GET http://127.0.0.2/ XAXAX\r\n\r\n",
        "CONNECT XAXAX HTTP/1.0\r\n\r\n",
        "CONNECT XAXAX:80 HTTP/1.0\r\n\r\n",
        "CONNECT 127.0.0.2:XAXAX HTTP/1.0\r\n\r\n",
        "CONNECT 127.0.0.2:80 XAXAX\r\n\r\n",
    );
}

sub getCommandarray {
    (
        "XAXAX: XAXAX\r\n\r\n",
        "User-Agent: XAXAX\r\n\r\n",
        "Host: XAXAX\r\n\r\n",
        "Host: XAXAX:80\r\n\r\n",
        "Host: somehost:XAXAX\r\n\r\n",
        "Accept: XAXAX\r\n\r\n",
        "Accept-Encoding: XAXAX\r\n\r\n",
        "Accept-Language: XAXAX\r\n\r\n",
        "Accept-Charset: XAXAX\r\n\r\n",
        "Connection: XAXAX\r\n\r\n",
        "Referer: XAXAX\r\n\r\n",
        "Referer: XAXAX://somehost.com/\r\n\r\n",
        "Referer: http://XAXAX/\r\n\r\n",
        "Referer: http://somehost.com/XAXAX\r\n\r\n",
        "Authorization: XAXAX\r\n\r\n",
        "From: XAXAX\r\n\r\n",
        "Charge-To: XAXAX\r\n\r\n",
        "Authorization: XAXAX",
        "Authorization: XAXAX : foo\r\n\r\n",
        "Authorization: foo : XAXAX\r\n\r\n",
        "If-Modified-Since: XAXAX\r\n\r\n",
        "If-Match: XAXAX\r\n\r\n",
        "If-None-Match: XAXAX\r\n\r\n",
        "If-Range: XAXAX\r\n\r\n",
        "If-Unmodified-Since: XAXAX\r\n\r\n",
        "Max-Forwards: XAXAX\r\n\r\n",
        "Proxy-Authorization: XAXAX\r\n\r\n",
        "ChargeTo: XAXAX\r\n\r\n",
        "Pragma: XAXAX\r\n\r\n",
        "Proxy-Connection: XAXAX\r\n\r\n",
        "Expect: XAXAX\r\n\r\n",
        "Range: XAXAX\r\n\r\n",
        "Range: bytes=1-XAXAX\r\n\r\n",
        "Range: bytes=0-1,XAXAX\r\n",
        "Content-Length: XAXAX\r\n\r\n",
        "Cookie: XAXAX\r\n\r\n",
        "TE: XAXAX\r\n\r\n",
        "Upgrade: XAXAX\r\nConnection: upgrade\r\n\r\n",
    );
}

sub getLogin {
    (
        "GET http://127.0.0.2/ HTTP/1.0\r\n",
        "POST http://127.0.0.2/ HTTP/1.0\r\n",
        "CONNECT 127.0.0.1:80 HTTP/1.1\r\n",
        "GET http://127.0.0.2/ HTTP/1.1\r\n",
        "POST http://127.0.0.2/ HTTP/1.1\r\n",
        "CONNECT 127.0.0.2:80 HTTP/1.0\r\n",
    );
}

sub testMisc {
    (
        "GET / HTTP/1.0\r\n"
            . "LotsOfHeaders: XAXAX\r\n" x 1024
            . "\r\n",

        "GET http:// HTTP/1.1\r\nRange: bytes=10-1\r\n\r\n",
    );
}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
