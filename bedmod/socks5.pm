package bedmod::socks5;

use strict;
use warnings;
#use diagnostics;

use Socket;

# socks5 plugin
#
# not yet tested, got bored just by looking at the protocol

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# create a new instance of this object
sub new {
    my $self = {
        username => '',
        password => '',
    };

    bless $self;
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# initialise some parameters
sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 1080;
    $self->{sport} = 0;
    $self->{vrfy}  = "";

    $self->usage() and exit unless $args{u} and $args{v};

    $self->{username} = $args{u};
    $self->{password} = $args{v};
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
    # all there is to test is the username as far as it seems...
    (
        "XAXAX\n",
        # if the programmer is clever enough he always receives the packet
        # in a buffer which is bigger than ~0x128 :)
        "\x05\x01\x00\x04\xFF\x10"
        ,    # check for buffer access which should give a gpf
        "\x05\x01\x00\x04\x50\x10"    # same here different value... lame :)
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to send to login ?
sub getLogin {                        # login procedure
    my $self   = shift;

    my $username = $self->{username} || '';
    my $password = $self->{password} || '';

    my $username_len = length($self->{username}) || 0;
    my $password_len = length($self->{password}) || 0;

    (
        #protocol version #nr. of authentication methods #username+password
        "\x05\x01\x02",

        #protocol #username len #username #pass len #password
        "\x05"
            . $username_len
            . $username
            . $password_len
            . $password,
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# here we can test everything besides buffer overflows and format strings
sub testMisc {()}

sub usage {
    print qq~ Parameters for the Socks5 plugin:
    -u <username>
    -v <password>

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
