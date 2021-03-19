#
# Quickly hacked Module to test some LPD Stuff,
# not everything ... yeah I am lazy too :)
#

package bedmod::lpd;

use strict;
use warnings;
#use diagnostics;

use Socket;

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# create a new instance of this object
sub new {
    bless {
        sport => 721,
    };
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# initialise some parameters
sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 515;
    $self->{vrfy}  = '';
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# how to quit ?
sub getQuit {
    ("\1\n");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to test without doing a login before
# ..mainly the login stuff *g*
sub getLoginarray {
    (
        "XAXAX",
        "\01XAXAX\n",
        "\02XAXAX\n",
        "\03XAXAX all\n",
        "\03default XAXAX\n",
        "\04XAXAX all\n",
        "\04default XAXAX\n",
        "\05XAXAX root all\n",
        "\05default XAXAX all\n",
        "\05default root XAXAX\n"
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# which commands does this protocol know ?
sub getCommandarray {
    # the XAXAX will be replaced with the buffer overflow / format string
    # place every command in this array you want to test
    (
        "\0294XAXAX001test\n", "\0294cfA001XAXAX\n",
        "\0394XAXAX001test\n", "\0394cfA001XAXAX\n",
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to send to login ?
sub getLogin {    # login procedure
    ("\02default\n");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# here we can test everything besides buffer overflows and format strings
sub testMisc {()}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
