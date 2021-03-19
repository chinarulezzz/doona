package bedmod::nntp;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check
# for NNTP server vulnerabilities.

sub new {
    bless {
        username => 'anonymous',
        password => 'password',
    };
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 119;
    $self->{vrfy}  = "HELP\r\n";

    $self->{username} = $args{u} if $args{u};
    $self->{password} = $args{v} if $args{v};

    # let's see if we got a correct login (skip if dump mode is set)
    return if $args{d};

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

    send(SOCKET, "authinfo user $self->{username}\r\n", 0)
        || die "\nUsername failed: $!\n";

    my $recvbuf = <SOCKET>;
    sleep 1;

    send(SOCKET, "authinfo pass $self->{password}\r\n", 0)
        || die "\nPassword failed: $!\n";

    do {
        $recvbuf = <SOCKET>;
        print $recvbuf;
        if ($recvbuf =~ "452") {
            print("Username or password incorrect, can't login\n");
            exit 1;
        }
        sleep 0.2;
        # 281 Authorization accepted
    } until ($recvbuf =~ "281");

    send(SOCKET, "QUIT\r\n", 0);
    close SOCKET;
}

sub getQuit {
    ("QUIT\r\n");
}

sub getLoginarray {
    my $self = shift;
    (
        "XAXAX\r\n",
        "authinfo XAXAX\r\n",
        "authinfo XAXAX XAXAX\r\n",
        "authinfo user XAXAX\r\nXAXAX\r\n",
        "authinfo user XAXAX\r\nauthinfo pass XAXAX\r\n",
        "authinfo user $self->{username}\r\nauthinfo pass XAXAX\r\n",
        "authinfo pass XAXAX\r\n",
        "authinfo simple XAXAX\r\n",
        "authinfo simple\r\nXAXAX XAXAX\r\n",
        "authinfo simple\r\n$self->{username} XAXAX\r\n",
        "authinfo generic XAXAX\r\n",
        "authinfo generic XAXAX XAXAX\r\n"
    );
}

sub getCommandarray {
    my $self = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    (
        "XAXAX\r\n",
        "authinfo XAXAX\r\n",
        "authinfo XAXAX XAXAX\r\n",
        "authinfo user XAXAX\r\nXAXAX\r\n",
        "authinfo user XAXAX\r\nauthinfo pass XAXAX\r\n",
        "authinfo user $self->{username}\r\nauthinfo pass XAXAX\r\n",
        "authinfo pass XAXAX\r\n",
        "authinfo simple XAXAX\r\n",
        "authinfo simple\r\nXAXAX XAXAX\r\n",
        "authinfo simple\r\n$self->{username} XAXAX\r\n",
        "authinfo generic XAXAX\r\n",
        "authinfo generic XAXAX XAXAX\r\n",
        "article XAXAX\r\n",
        "body XAXAX\r\n",
        "charset XAXAX\r\n",
        "check XAXAX\r\n",
        "group XAXAX\r\n",
        "head XAXAX\r\n",
        "help XAXAX\r\n",
        "ihave XAXAX\r\n",
        "list XAXAX\r\n",
        "list active XAXAX\r\n",
        "list newsgroups XAXAX\r\n",
        "listgroup XAXAX\r\n",
        "mode XAXAX\r\n",
        "mode stream XAXAX\r\n",
        "mode reader XAXAX\r\n",
        "newgroups XAXAX XAXAX XAXAX XAXAX\r\n",
        "newnews XAXAX XAXAX XAXAX XAXAX XAXAX\r\n",
        "stat XAXAX\r\n",
        "takethis XAXAX\r\n",
        "xgtitle XAXAX\r\n",
        "xhdr XAXAX\r\n",
        "xhdr header XAXAX\r\n",
        "xindex XAXAX\r\n",
        "xover XAXAX\r\n",
        "xover XAXAX\r\n",
        "xpat XAXAX XAXAX XAXAX XAXAX\r\n",
        "xpath XAXAX\r\n",
        "xreplic XAXAX\r\n",
        "xthread XAXAX\r\n",
        "xgtitle\r\n"
    );
}

sub getLogin {
    my $self = shift;
    (
        "authinfo user $self->{username}\r\n"
            . "authinfo pass $self->{password}\r\n",
    );
}

sub testMisc {()}

sub usage {
    print qq~ NNTP module specific options:
 -u <username> = Username to use for authentication (default: anonymous)
 -v <password> = Password to use for authentication (default: password)

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
