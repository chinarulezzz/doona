package bedmod::whois;

use strict;
use warnings;
#use diagnostics;

use Socket;

# lame whois plugin :)

# create a new instance of this object
sub new {
    bless {};
}

# initialise some parameters
sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 43;
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
        "XAXAX\r\n",
        "?XAXAX\r\n",
        "!XAXAX\r\n",
        ".XAXAX\r\n",
        "XAXAX...\r\n",
        "*XAXAX\r\n",
        "XAXAX.tld\r\n",
        "domain.XAXAX\r\n",
    );
}

# what to send to login ?
sub getLogin {
    ('');
}

sub testMisc {()}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
