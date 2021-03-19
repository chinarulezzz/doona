package bedmod::dict;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to BED, to check
# for DICT server vulnerabilities.

# Authentication is not implemented for this module.
# There's a bunch of placeholders which will help
# should you wish to implement authentication.
# For more information, review:
# - RFC 2229 (DICT) - section 3.11 - The AUTH Command
# - RFC 1939 (POP) - section 4 - The AUTHORIZATION State

sub new {
    # Authentication is not implemented for this module.
    # These default values are used to fuzz auth verbs:
    my $self = {
        username => 'anonymous',
        password => 'password',
    };

    bless $self;
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = 'tcp';
    $self->{port}  = $args{p} || 2628;
    $self->{vrfy}  = "HELP\r\n";

    # Authentication is not implemented for this module.
    # This is a placeholder
    $self->{username} = $args{u} if $args{u};
    $self->{password} = $args{v} if $args{v};

    # Test connection to target (skip if dump mode is set)
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

    # Authentication is not implemented for this module.
    # so we grab the banner instead
    send(SOCKET, "\r\n", 0);
    my $recvbuf = <SOCKET>;
    print $recvbuf;

    # The psuedo-code below checks if the server requires authentication.
    #send(SOCKET,
    #     "AUTH $self->{username} md5(<timestamp@host>$self->{password})\r\n",
    #     0)
    #   || die "\nAuthentication failed: $!\n";
    #do {
    #    $recvbuf = <SOCKET>;
    #    print $recvbuf;
    #    if ($recvbuf =~ "530") {
    #        print "Access is denied, can't login\n";
    #        exit 1;
    #    }
    #    if ($recvbuf =~ "531") {
    #        print "Username or password incorrect, can't login\n";
    #        exit 1;
    #    }
    #    sleep 0.2;
    #    # 230 Authentication successful
    #} until ($recvbuf =~ "230");
    #send(SOCKET, "QUIT\r\n", 0);
    close(SOCKET);
}

sub getQuit {
    ("QUIT\r\n");
}

sub getLoginarray {
    my $self = shift;

    # Authentication is not implemented for this module.
    # so we return an empty string
    return ("");

    # This is a placeholder
    return (
        "XAXAX\r\n",
        "AUTH XAXAX\r\n",
        "AUTH XAXAX XAXAX\r\n",
        "AUTH $self->{username} XAXAX\r\n",
        "SASLAUTH XAXAX\r\nSASLRESP XAXAX\r\n",
        "SASLAUTH XAXAX XAXAX\r\nSASLRESP XAXAX\r\n"
    );
}

sub getCommandarray {
    my $self = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them.
    (
        "XAXAX\r\n",
        "AUTH XAXAX\r\n",
        "AUTH XAXAX XAXAX\r\n",
        "AUTH $self->{username} XAXAX\r\n",
        "SASLAUTH XAXAX\r\nSASLRESP XAXAX\r\n",
        "SASLAUTH XAXAX XAXAX\r\nSASLRESP XAXAX\r\n",
        "DEFINE ! XAXAX\r\n",
        "DEFINE XAXAX XAXAX\r\n",
        "MATCH ! XAXAX XAXAX\r\n",
        "MATCH XAXAX XAXAX XAXAX\r\n",
        "SHOW XAXAX\r\n",
        "SHOW INFO XAXAX\r\n",
        "CLIENT XAXAX\r\n",
        "OPTION XAXAX\r\n"
    );
}

sub getLogin {
    my $self = shift;

    # Authentication is not implemented for this module.
    # so we return an empty string
    return ("");

    # This is a placeholder
    return ("AUTH $self->{username} $self->{password}\r\n");
}

sub testMisc {()}

sub usage {
    print qq~ DICT module specific options:
 -u <username> = Username to use for authentication (default: anonymous)
 -v <password> = Password to use for authentication (default: password)

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
