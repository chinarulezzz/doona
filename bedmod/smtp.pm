package bedmod::smtp;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check
# for smtp server vulnerabilities.

sub new {
    bless {};
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 25;

    $self->usage() and exit unless $args{u};

    # get info necessary for SMTP
    $self->{mail} = $args{u};
    $self->{vrfy} = "HELP\r\n";
}

sub getQuit{
    ("QUIT\r\n");
}

sub getLoginarray {
    (
        "XAXAX\r\n",
        "HELO XAXAX\r\n",
        "EHLO XAXAX\r\n",
        "HELP XAXAX\r\n",
    );
}

sub getCommandarray {
    my $self = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    (
        "EXPN XAXAX\r\n",
        "MAIL FROM: XAXAX\r\n",
        "MAIL FROM: <XAXAX>\r\n",
        "MAIL FROM: <$self->{mail}> XAXAX\r\n",
        "MAIL FROM: <$self->{mail}> RET=XAXAX\r\n",
        "MAIL FROM: <$self->{mail}> ENVID=XAXAX\r\n",
        "ETRN XAXAX\r\n",
        "ETRN \@XAXAX\r\n",
        "MAIL FROM: <$self->{mail}>\r\nRCPT TO: <XAXAX>\r\n",
        "MAIL FROM: <$self->{mail}>\r\nRCPT TO: <$self->{mail}> XAXAX\r\n",
        "MAIL FROM: <$self->{mail}>\r\nRCPT TO: <$self->{mail}> NOTIFY=XAXAX\r\n",
        "MAIL FROM: <$self->{mail}>\r\nRCPT TO: <$self->{mail}> ORCPT=XAXAX\r\n",
        "HELP XAXAX\r\n",
        "VRFY XAXAX\r\n",
        "RCTP TO: XAXAX\r\n",
        "RCTP TO: <XAXAX>\r\n",
        "RCPT TO: <$self->{mail}> XAXAX\r\n",
        "RCPT TO: <$self->{mail}> NOTIFY=XAXAX\r\n",
        "RCPT TO: <$self->{mail}> ORCPT=XAXAX\r\n",
        "RSET XAXAX\r\n",
        "AUTH mechanism XAXAX\r\n",
        "DATA XAXAX\r\n",
        "DATA\r\nXAXAX\r\n.",
        "XAXAX\r\n"
    );
}

sub getLogin {
    (
        "HELO doona.pl\r\n",
        "EHLO doona.pl\r\n",
    );
}

sub testMisc {()}

sub usage {
    print qq~ Parameters for the SMTP plugin:
    -u <valid mail address at target host>

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
