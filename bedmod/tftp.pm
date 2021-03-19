package bedmod::tftp;

use strict;
use warnings;
#use diagnostics;

use Socket;

# lame tftp plugin :)

# create a new instance of this object
sub new {
    bless {};
}

# initialise some parameters
sub init{
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'udp';
    $self->{port}  = $args{p} || 69;
    $self->{sport} = 0;
    $self->{vrfy}  = '';
}

# how to quit ?
sub getQuit {
    ('');
}

# what to test without doing a login before
sub getLoginarray {
    ('');
}

# which commands does this protocol know ?
sub getCommandarray {
    # the XAXAX will be replaced with the buffer overflow / format string
    # place every command in this array you want to test
    (
        "XAXAX", # B0F
        "\x00\x01XAXAX\x00netascii\x00", #RRQ
        "\x00\x01XAXAX\x00octet\x000", #RRQ
        "\x00\x01XAXAX\x00mail\x00", #RRQ
        "\x00\x01"."fuzz\x00XAXAX\x00", #RRQ
        "\x00\x02\x41\x00XAXAX\x00", #WRQ
        "\x00\x03\x41\x00XAXAX\x00", #DATA?
        "\x0c\x0dXAXAX\x00",
    );
}

# what to send to login ?
sub getLogin {
    ('');
}

# here we can test everything besides buffer overflows and format strings
sub testMisc {()};

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
