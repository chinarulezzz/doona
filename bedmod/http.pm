package bedmod::http;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check
# for http server vulnerabilities.

sub new {
    bless {};
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto}   = 'tcp';
    $self->{healthy} = '';
    $self->{port}    = $args{p} || 80;

    return if $args{d};

    die "\nHTTP server failed health check!\n"
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
        #print "Set healthy: $resp";
    }
    return $resp =~ m/^$self->{healthy}$/;
}


sub getQuit {
    ("\r\n\r\n");
}

sub getLoginarray {
    (
        "XAXAX\r\n\r\n",
        "XAXAX / HTTP/1.0\r\n\r\n",
        "HEAD XAXAX HTTP/1.0\r\n\r\n",
        "HEAD /XAXAX HTTP/1.0\r\n\r\n",
        "HEAD /?XAXAX HTTP/1.0\r\n\r\n",
        "HEAD / XAXAX\r\n\r\n",
        "HEADXAXAX / HTTP/1.0\r\n\r\n",
        "GET XAXAX HTTP/1.0\r\n\r\n",
        "GET /XAXAX HTTP/1.0\r\n\r\n",
        "GET /XAXAX.html HTTP/1.0\r\n\r\n",
        "GET /index.XAXAX HTTP/1.0\r\n\r\n",
        "GET /~XAXAX HTTP/1.0\r\n\r\n",
        "GET /?XAXAX HTTP/1.0\r\n\r\n",
        "GET /?XAXAX=x HTTP/1.0\r\n\r\n",
        "GET /?x=XAXAX HTTP/1.0\r\n\r\n",
        "GET / XAXAX\r\n\r\n",
        "GET / HTTP/XAXAX\r\n\r\n",
        "GET /XAXAX\r\n\r\n",
        "GETXAXAX / HTTP/1.0\r\n\r\n",
        "POST XAXAX HTTP/1.0\r\n\r\n",
        "POST /XAXAX HTTP/1.0\r\n\r\n",
        "POST /?XAXAX HTTP/1.0\r\n\r\n",
        "POST / XAXAX\r\n\r\n",
        "POST /XAXAX\r\n\r\n",
        "POST / HTTP/1.0\r\n\r\nXAXAX\r\n\r\n",
        "POST / HTTP/1.0\r\nContent-length: 10\r\n\r\nXAXAX\r\n\r\n",

        "POST / HTTP/1.0\r\nContent-Type: multipart/form-data; "
            . "boundary=---XAXAX\r\n\r\n---XAXAX--\r\n\r\n",

        "POST / HTTP/1.0\r\nContent-Type: multipart/form-data; "
            . "boundary=---AAAAA\r\n\r\n---AAAAA\r\n"
            . "Content-Disposition: form-data; name=\"XAXAX\"\r\n\r\n"
            . "test\r\n---AAAAA--\r\n\r\n",

        "POST / HTTP/1.0\r\nContent-Type: multipart/form-data; "
            . "boundary=---AAAAA\r\n\r\n---AAAAA\r\n"
            . "Content-Disposition: form-data; name=\"test\"\r\n\r\nXAXAX\r\n"
            . "---AAAAA--\r\n\r\n",

        "OPTIONS XAXAX HTTP/1.0\r\n\r\n",
        "OPTIONS /XAXAX HTTP/1.0\r\n\r\n",
        "OPTIONS / XAXAX\r\n\r\n",
        "PUT XAXAX HTTP/1.0\r\n\r\n",
        "PUT /XAXAX HTTP/1.0\r\n\r\n",
        "PUT / XAXAX\r\n\r\n",
        "TRACE XAXAX HTTP/1.0\r\n\r\n",
        "TRACE /XAXAX HTTP/1.0\r\n\r\n",
        "TRACE / XAXAX\r\n\r\n",
        "TRACK XAXAX HTTP/1.0\r\n\r\n",
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
        "Date: XAXAX\r\n\r\n",
        "Referer: XAXAX\r\n\r\n",
        "Referer: XAXAX://somehost.com/\r\n\r\n",
        "Referer: http://XAXAX/\r\n\r\n",
        "Referer: http://somehost.com/XAXAX\r\n\r\n",
        "Authorization: XAXAX\r\n\r\n",
        "From: XAXAX\r\n\r\n",
        "Charge-To: XAXAX\r\n\r\n",
        "Authorization: XAXAX\r\n\r\n",
        "Authorization: Basic XAXAX\r\n\r\n",
        "Authorization XAXAX: Basic AAAAAA\r\n\r\n",
        "Authorization: Digest XAXAX\r\n\r\n",

        "Authorization: Digest username=\"XAXAX\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=auth,nc=00000001,cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"XAXAX\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=auth,nc=00000001,cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"XAXAX\",uri=\"/index.html\",qop=auth,nc=00000001,"
            . "cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",uri=\"XAXAX\","
            . "qop=auth,nc=00000001,cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=XAXAX,nc=00000001,cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=auth,nc=XAXAX,cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=auth,nc=00000001,cnonce=\"XAXAX\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=auth,nc=00000001,cnonce=\"0a4f113b\","
            . "response=\"XAXAX\","
            . "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n\r\n",

        "Authorization: Digest username=\"doona\",realm=\"d\@ona.com\","
            . "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\","
            . "uri=\"/index.html\",qop=auth,nc=00000001,cnonce=\"0a4f113b\","
            . "response=\"6629fae49393a05397450978507c4ef1\","
            . "opaque=\"XAXAX\"\r\n\r\n",

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
        "Expect: XAXAX\r\n\r\n",
        "Range: XAXAX\r\n\r\n",
        "Range: bytes=1-XAXAX\r\n\r\n",
        "Range: bytes=0-1,XAXAX\r\n",
        "Content-Length: XAXAX\r\n\r\n",
        "Content-Type: XAXAX\r\n\r\n",
        "Content-Type: text/html; XAXAX\r\n\r\n",
        "Content-Type: XAXAX/html; charset=ISO-8859-4\r\n\r\n",
        "Content-Type: text/XAXAX; charset=ISO-8859-4\r\n\r\n",
        "Content-Type: text/html; XAXAX=ISO-8859-4\r\n\r\n",
        "Content-Type: text/html; charset=XAXAX\r\n\r\n",
        "Content-Encoding: XAXAX\r\n\r\n",
        "Content-Encoding: XAXAX\r\nCache-control: no-transform\r\n\r\n",
        "Content-Language: XAXAX\r\n\r\n",
        "Cache-control: XAXAX\r\n\r\n",
        "Cache-control: max-age=XAXAX\r\n\r\n",
        "Cache-control: min-fresh=XAXAX\r\n\r\n",
        "Cache-control: max-stale=XAXAX\r\n\r\n",
        "Cookie: XAXAX\r\n\r\n",
        "Cookie: XAXAX=abc\r\n\r\n",
        "Cookie: abc=XAXAX\r\n\r\n",
        # The meaning of the Content-Location header in PUT or POST requests is
        # undefined; servers are free to ignore it in those cases.
        "Content-Location: XAXAX\r\n\r\n",
        "Content-Language: XAXAX\r\n\r\n",
        "Content-MD5: XAXAX\r\n\r\n",
        "Content-Range: 0-XAXAX/1024\r\n\r\n",
        "Content-Range: XAXAX-500/1024\r\n\r\n",
        "Content-Range: 0-500/XAXAX\r\n\r\n",
        "X-Headr: XAXAX\r\n XAXAX\r\n\r\n",
        "TE: XAXAX\r\n\r\n",
        "Trailer: XAXAX\r\n\r\n",
        "Transfer-Encoding: XAXAX\r\n\r\n",
        "Via: XAXAX\r\n\r\n",
        "X-Forwarded-For: XAXAX\r\n\r\n",
        "Upgrade: XAXAX/1.0\r\nConnection: upgrade\r\n\r\n",
    );
}

sub getLogin {
    (
        "GET / HTTP/1.0\r\n",
        "POST / HTTP/1.0\r\n",
        "HEAD / HTTP/1.0\r\n",
        "GET / HTTP/1.1\r\n",
        "OPTIONS / HTTP/1.0\r\n",
        "PUT / HTTP/1.0\r\n",
        "TRACE / HTTP/1.0\r\n",
    );
}

sub testMisc {
    (
        "GET / HTTP/1.0\r\n"
            . "LotsOfHeaders: XAXAX\r\n" x 1024
            . "\r\n",
    );
}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
