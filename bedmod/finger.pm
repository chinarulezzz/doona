package bedmod::finger;

use strict;
use warnings;
#use diagnostics;

use Socket;

# lame finger plugin :)

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# create a new instance of this object
sub new {
    bless {};
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# initialise some parameters
sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 79;
    $self->{sport} = 0;
    $self->{vrfy}  = "root\n";
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
    # the XAXAX will be replaced with the buffer overflow / format string
    # place every command in this array you want to test
    (
        "XAXAX\r\n",
        "\@XAXAX\r\n",
        "XAXAX\@\r\n",
        "XAXAX\@XAXAX\r\n"
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to send to login ?
sub getLogin {    # login procedure
    ("");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# here we can test everything besides buffer overflows and format strings
sub testMisc {()}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
