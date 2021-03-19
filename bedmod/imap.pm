package bedmod::imap;

use strict;
use warnings;
#use diagnostics;

use Socket;

# imap plugin for bed2

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# create a new instance of this object
sub new {
    bless {
        username => '',
        password => '',
    };
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# initialise some parameters
sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 143;

    $self->usage() and exit unless $args{u} and $args{v};

    $self->{username} = $args{u};
    $self->{password} = $args{v};

    # how can bed check that the server is still alive
    $self->{vrfy} = "A001 NOOP\r\n";
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# how to quit ?
sub getQuit {
    ("A001 LOGOUT\r\n");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to test without doing a login before
# ..mainly the login stuff *g*
sub getLoginarray {
    my $self = shift;
    (
        "A001 AUTHENTICATE XAXAX\r\n",
        "A001 LOGIN XAXAX\r\n",
        "A001 LOGIN $self->{username} XAXAX\r\n"
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# which commands does this protocol know ?
sub getCommandarray {
    my $self = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # place every command in this array you want to test
    (
        "A001 CREATE myTest\r\n",    # just for testing...
        "FXXZ CHECK XAXAX\r\n",
        "LIST XAXAX\r\n",
        "A001 SELECT XAXAX\r\n",
        "A001 EXAMINE XAXAX\r\n",
        "A001 CREATE XAXAX\r\n",
        "A001 DELETE XAXAX\r\n",
        "A001 RENAME XAXAX\r\n",
        "A001 CREATE test\r\nA001RENAME test XAXAX\r\n",
        "A001 SUBSCRIBE XAXAX\r\n",
        "A001 UNSUBSCRIBE XAXAX\r\n",
        "A001 LIST XAXAX aa \r\n",
        "A001 LIST aa XAXAX\r\n",
        "A001 LIST * XAXAX\r\n",
        "A001 LSUB aa XAXAX\r\n",
        "A001 LSUB XAXAX aa \r\n",    # aa should be ""
        "A001 STATUS XAXAX\r\n",
        "A001 STATUS inbox (XAXAX)\r\n",
        "A001 APPEND XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 SEARCH XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 FETCH XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 FETCH 1:2 XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 STORE XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 STORE 1:2 XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 COPY XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 COPY 1:2 XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 UID XAXAX\r\n",
        "A001 SELECT myTest\r\nA001 UID FETCH XAXAX\r\n",
        "A001 UID XAXAX\r\n",
        "A001 CAPABILITY XAXAX\r\n",
        "A001 DELETEACL XAXAX\r\n",
        "A001 GETACL XAXAX\r\n",
        "A001 LISTRIGHTS XAXAX\r\n",
        "A001 MYRIGHTS XAXAX\r\n",
        "A001 XAXAX\r\n"
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to send to login ?
sub getLogin {    # login procedure
    my $self = shift;
    ("A001 LOGIN $self->{username} $self->{password}\r\n");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# here we can test everything besides buffer overflows and format strings
sub testMisc {()}

sub usage {
    print qq~ Parameters for the imap plugin:
    -u <username>
    -v <password>

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
