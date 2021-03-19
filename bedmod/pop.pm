package bedmod::pop;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check
# for pop server vulnerabilities.

sub new {
    bless {
        username => '',
        password => '',
    };
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 110;

    $self->usage() unless $args{u} and $args{v};

    $self->{username} = $args{u};
    $self->{password} = $args{v};
    $self->{vrfy}     = "NOOP\r\n";

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

    send(SOCKET, "USER $self->{username}\r\n", 0)
        || die "\nUSER failed: $!\n";

    my $recvbuf = <SOCKET>;
    sleep 1;

    send(SOCKET, "PASS $self->{password}\r\n", 0)
        || die "\nPASS failed: $!\n";

    $recvbuf = <SOCKET>;
    if ($recvbuf =~ "-ERR") {
        print "\nUsername or Password incorrect, can't login\n";
        exit 1;
    }

    send(SOCKET, "QUIT\r\n", 0);
}

sub getQuit {
    ("QUIT\r\n");
}

sub getLoginarray {
    my $self = shift;
    (
        "USER XAXAX\r\n",
        "USER $self->{username}\r\nPASS XAXAX\r\n",
        "APOP XAXAX aaa\r\n",
        "APOP $self->{username} XAXAX\r\n"
    );
}

sub getCommandarray {
    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    (
        "LIST XAXAX\r\n",
        "STAT XAXAX\r\n",
        "NOOP XAXAX\r\n",
        "APOP XAXAX\r\n",
        "RSET XAXAX\r\n",
        "RETR XAXAX\r\n",
        "DELE XAXAX\r\n",
        "TOP XAXAX 1\r\n",
        "TOP 1 XAXAX\r\n",
        "UIDL XAXAX\r\n",
    );
}

sub getLogin {
    my $self = shift;
    (
        "USER $self->{username}\r\n",
        "PASS $self->{password}\r\n",
    );
}

sub testMisc {()}

sub usage {
    print qq~ Parameters for the POP plugin:
    -u <username>
    -v <password>

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
