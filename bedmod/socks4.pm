package bedmod::socks4;

use strict;
use warnings;
#use diagnostics;

use Socket;

# socks4 plugin (anyone still using this?)
# pretty few to test, i did not even find an rfc for this
# protocol *yuck*

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# create a new instance of this object
sub new {
    my $self = {
        username => '',
    };

    bless $self;
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# initialise some parameters
sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 1080;
    $self->{sport} = 0;
    $self->{vrfy}  = '';

    $self->usage() and exit unless $args{u};

    $self->{username} = $args{u};
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# how to quit ?
sub getQuit {
    ("");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to test without doing a login before
# ..mainly the login stuff *g*
sub getLoginarray {
    ("");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# which commands does this protocol know ?
sub getCommandarray {
    my $self = shift;

    # all there is to test is the username as far as it seems...
    (
        "XAXAX\n",
        # we use protocol version 04
        # destination port is 6668
        # destination ip is 192.168.0.1
        "\x04\x01\x1a\x0c\xc0\xA8\x00\x01XAXAX\x00",    # connect
        "\x04\x02\x1a\x0c\xc0\xA8\x00\x01XAXAX\x00",    # bind
        "\x04\x01\x1a\x0c\x00\x00\x00\x01$self->{username}\x00XAXAX", # connect socks4a
        "\x04\x02\x1a\x0c\x00\x00\x00\x01$self->{username}\x00XAXAX" # bind socks4a
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to send to login ?
sub getLogin {    # login procedure
    ('');
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# here we can test everything besides buffer overflows and format strings
sub testMisc {()}

sub usage {
    print qq~ Parameters for the Socks4 plugin:
     -u <username>

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
