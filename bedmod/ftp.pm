package bedmod::ftp;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check
# for ftp server vulnerabilities.

sub new {
    my $self = {
        healthy  => '',
        username => 'anonymous',
        password => 'user@this.bed',
    };

    bless $self;
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 21;

    $self->{username} = $args{u} if $args{u};
    $self->{password} = $args{v} if $args{v};
    $self->{vrfy}     = "PWD\r\n";

    # let's see if we got a correct login (skip if dump mode is set)
    return if $args{d};

    die "\nFTP server failed health check!\n"
        unless $self->health_check();

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
    sleep 1; # some ftp's need some time to reply

    send(SOCKET, "PASS $self->{password}\r\n", 0)
        || die "\nPASS failed: $!\n";

    do {
        $recvbuf = <SOCKET>;
        print $recvbuf;
        if ($recvbuf =~ "530") {
            print "\nUsername or Password incorrect, can't login\n";
            exit 1;
        }
        sleep 0.2;
    } until ($recvbuf =~ "230");

    send(SOCKET, "QUIT\r\n", 0);
    close SOCKET;
}

sub health_check {
    my $self = shift;

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

    my $recv;
    do {
        $recv = <SOCKET>;
        sleep 0.2;
    } until ($recv =~ /^220/);

    send(SOCKET, "PASS\r\n", 0);

    $recv = <SOCKET>;

    if (!$self->{healthy}) {
        $self->{healthy} = $recv if $recv =~ /^\d\d\d/;
    }
    return $recv =~ /^$self->{healthy}$/;
}

sub getQuit {
    ("QUIT\r\n");
}

sub getLoginarray {
    my $self = shift;
    (
        "XAXAX\r\n",
        "USER XAXAX\r\n",
        "USER XAXAX\r\nPASS password\r\n",
        "USER anonymous\r\nPASS XAXAX\r\n",

        "USER XAXAX\r\nPASS password\r\nUSER "
            . "$self->{username}\r\nPASS XAXAX\r\n",

        "USER $self->{username}\r\nPASS XAXAX\r\n",
        "PASS XAXAX\r\n"
    );
}

sub getCommandarray {
    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    (
        "XAXAX\r\n",
        "XAXAX 123\r\n",
        "ABOR XAXAX\r\n",
        "ACCL XAXAX\r\n",
        "ACCT XAXAX\r\n",
        "ADAT XAXAX\r\n",
        "ALLO XAXAX\r\n",
        "APPE XAXAX\r\n",
        "APPE /XAXAX\r\n",
        "CCC XAXAX\r\n",
        "CDUP XAXAX\r\n",
        "CONF XAXAX\r\n",
        "CWD XAXAX\r\n",
        "CEL XAXAX\r\n",
        "DELE XAXAX\r\n",
        "ENC XAXA\r\n",
        "EPRT XAXAX\r\n",
        "EPRT |XAXAX|127.0.0.1|6275|\r\n",
        "EPRT |1|XAXAX|6275|\r\n",
        "EPRT |1|127.0.0.1|XAXAX|\r\n",
        "EPSV XAXAX\r\n",
        "FEAT XAXAX\r\n",
        "HELP XAXAX\r\n",
        "LANG XAXAX\r\n",
        "LIST XAXAX\r\n",
        "LIST -XAXAX\r\n",
        "LIST *XAXAX\r\n",
        "LOCK XAXAX\r\n",
        "LOCK / XAXAX\r\n",
        "LPRT XAXAX\r\n",
        "LPSV XAXAX\r\n",
        "MDTM XAXAX\r\n",
        "MDTM XAXAX file.txt\r\n",
        "MDTM 19990929043300 XAXAX\r\n",
        "MDTM 20031111111111+ XAXAX\r\n",
        "MIC XAXAX\r\n",
        "MLST XAXAX\r\n",
        "MODE XAXAX\r\n",
        "MKD XAXAX\r\n",
        "MKD XAXAX\r\nCWD XAXAX\r\n",
        "MKD XAXAX\r\nDELE XAXAX\r\n",
        "MKD XAXAX\r\nRMD XAXAX\r\n",
        "MKD XAXAX\r\nXRMD XAXAX\r\n",
        "NLST XAXAX\r\n",
        "NLST ~XAXAX\r\n",
        "NOOP XAXAX\r\n",
        "OPTS XAXAX\r\n",
        "PASS XAXAX\r\n",
        "PASV XAXAX\r\n",
        "PBSZ XAXAX\r\n",
        "PORT XAXAX\r\n",
        "PWD XAXAX\r\n",
        "QUOTE XAXAX\r\n",
        "REIN XAXAX\r\n",
        "REST XAXAX\r\n",
        "RETR XAXAX\r\n",
        "RMD XAXAX\r\n",
        "RNFR XAXAX\r\n",
        "RNTO XAXAX\r\n",
        "RNFR XAXAX\r\nRNTO XAXAX\r\n",
        "SITE XAXAX\r\n",
        "SITE EXEC XAXAX\r\n",
        "SITE GROUPS XAXAX\r\n",
        "SITE CDPATH XAXAX\r\n",
        "SITE ALIAS XAXAX\r\n",
        "SITE INDEX XAXAX\r\n",
        "SITE MINFO 20001010101010 XAXAX\r\n",
        "SITE NEWER 20001010101010 XAXAX\r\n",
        "SITE GPASS XAXAX\r\n",
        "SITE GROUP XAXAX\r\n",
        "SITE HELP XAXAX\r\n",
        "SITE IDLE XAXAX\r\n",
        "SITE CHMOD XAXAX\r\n",
        "SITE CHMOD 777 XAXAX\r\n",
        "SITE UMASK XAXAX\r\n",
        "SIZE XAXAX\r\n",
        "SIZE /XAXAX\r\n",
        "SMNT XAXAX\r\n",
        "STOU XAXAX\r\n",
        "STRU XAXAX\r\n",
        "STOR XAXAX\r\n",
        "STAT XAXAX\r\n",
        "SYST XAXAX\r\n",
        "TYPE XAXAX\r\n",
        "USER XAXAX\r\n",
        "UNLOCK XAXAX\r\n",
        "UNLOCK / XAXAX\r\n",
        "XCUP XAXAX\r\n",
        "XCWD XAXAX\r\n",
        "XMD5 XAXAX\r\n",
        "XMKD XAXAX\r\n",
        "XPWD XAXAX\r\n",
        "XRCP XAXAX\r\n",
        "XRMD XAXAX\r\n",
        "XRSQ XAXAX\r\n",
        "XSEM XAXAX\r\n",
        "XSEN XAXAX\r\n",
    );
}

sub getLogin {    # login procedure
    my $self = shift;
    ("USER $self->{username}\r\nPASS $self->{password}\r\n");
}

sub testMisc {
    my $self = shift;
    return;    # Directory traversal code is buggy an not really what I want
               # test for bof in login / user ?
               # test for the availability to abuse this host for portscanning ?

    # test for possible directory traversal bugs...
    print "*Directory traversal\n";

    my @traversal = (
        "...",            "%5c..%5c",,  "%5c%2e%2e%5c",
        "/././..",        "/...",       "/......", "\\...",
        "...\\",          "....",       "*",       "\\*",
        "\\....",         "*\\\\.....", "/..../",  "/../../../",
        "\\..\\..\\..\\", "\@/..\@/.."
    );
    for my $Directory (@traversal) {
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

        sleep 2; # some ftp's need some time to reply

        my $recvbuf = <SOCKET>;

        send(SOCKET, "PASS $self->{password}\r\n", 0)
            || die "\nPASS failed: $!\n";

        sleep 2; # some ftp's need some time to reply

        $recvbuf = <SOCKET>
            || die "\nLogin failed $!\n";

        send(SOCKET, "PWD\r\n", 0); # get old directory

        sleep 1;

        my $curDir = <SOCKET>;

        send(SOCKET, "CWD $Directory\r\n", 0); # send the traversal string

        # clear the buffer, by waiting for :  501 550 250 553
        do {
            $recvbuf = <SOCKET>;
        } while (($recvbuf !~ /550/)
            &&   ($recvbuf !~ /250/)
            &&   ($recvbuf !~ /553/)
            &&   ($recvbuf !~ /501/)); # receive answer

        send(SOCKET, "PWD\r\n", 0); # get new directory

        my $newDir = <SOCKET>;

        # compare the directories, and report a problem if they are not equal
        if ($curDir ne $newDir) {
            print "Directory Traversal ($curDir => $newDir) " .
                  "possible with $Directory \n";
        }
        send(SOCKET, "QUIT\r\n", 0);    # logout
        close SOCKET;                   # close connection
    }
    return ();
}

sub usage {
    print qq~ FTP Module specific options:
 -u <username> = Username to use for authentication (default: anonymous)
 -v <password> = Password to use for authentication (default: user\@this.bed)

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
