package bedmod::pjl;

use strict;
use warnings;
#use diagnostics;

use Socket;

# Plugin to check PJL Printer
# written to test a Lexmark T522
#
# i didnt read the pjl rfc or whatever just included
# the stuff if found by a quick google search :)

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

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 9100;
    $self->{vrfy}  = '';
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# how to quit ?
sub getQuit {
    ("\33%-12345X\n");
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# we got no login procedure...
sub getLoginarray {
    ('');
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# which commands does this protocol know ?
sub getCommandarray {
    # the XAXAX will be replaced with the buffer overflow / format string
    # here we go with our commands
    my $PI = "\33%-12345X\@PJL";    #  \n\@PJL
    (
        $PI . " ENTER XAXAX\n",
        $PI . " ENTER LANGUAGE = XAXAX\n",
        $PI . " JOB XAXAX\n",
        $PI . " JOB NAME = XAXAX\n",
        $PI . " JOB NAME = \"foo\" START = XAXAX\n",
        $PI . " JOB NAME = \"foo\" END = XAXAX\n",
        $PI . " JOB NAME = \"foo\" PASSWORD = XAXAX\n",
        $PI . " EOJ XAXAX\n",
        $PI . " EOJ NAME = XAXAX\n",
        $PI . " DEFAULT XAXAX\n",
        $PI . " DEFAULT LPARM: XAXAX\n",
        $PI . " DEFAULT IPARM: XAXAX\n",
        $PI . " SET XAXAX\n",
        $PI . " SET LPARM: XAXAX\n",
        $PI . " SET IPARM: XAXAX\n",
        $PI . " INQUIRE XAXAX\n",
        $PI . " INQUIRE LPARM: XAXAX\n",
        $PI . " INQUIRE IPARM: XAXAX\n",
        $PI . " DINQUIRE XAXAX\n",
        $PI . " DINQUIRE LPARM: XAXAX\n",
        $PI . " DINQUIRE IPARM: XAXAX\n",
        $PI . " INFO XAXAX\n",
        $PI . " ECHO XAXAX\n",
        $PI . " USTATUS XAXAX\n",
        $PI . " USTATUS A = XAXAX\n",
        $PI . " OPMSG DISPLAY = XAXAX\n",
        $PI . " RDYMSG DISPLAY = XAXAX\n",
        $PI . " STMSG DISPLAY = XAXAX\n",
        $PI . " COMMENT XAXAX\n",
        $PI . " SET PAGEPROTECT = XAXAX\n",
        $PI . " SET LIMAGEENHANCE = XAXAX\n",
        $PI . " LDPARM : PCL LCOLOREXTENSIONS = XAXAX\n",
        $PI . " LJOBINFO XAXAX\n",
        $PI . " LJOBINFO USERID = XAXAX\n",
        $PI . " LJOBINFO HOSTID = XAXAX\n",
    );
}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# what to send to login ?
sub getLogin {('')}

# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# here we can test everything besides buffer overflows and format strings
sub testMisc {()}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
