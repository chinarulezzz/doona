package bedmod::irc;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to bed, to check
# for irc server vulnerabilities.

sub new {
    bless {};
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 6667;
    $self->{vrfy}  = "uk\r\n"; # server should reply with unknown command
}

sub getQuit {
    ("QUIT\r\n");
}

sub getLoginarray {
    (
        "XAXAX\r\n",
        "USER XAXAX 0 cc :dd\r\n",
        "USER aa XAXAX cc :dd\r\n",
        "USER aa 0 XAXAX :dd\r\n",
        "USER aa 0 cc :XAXAX\r\n",
        "USER aa 0 cc XAXAX\r\n",
        "USER aa 0 cc :dd XAXAX\r\n", # realname may contain spaces
        "USER aa 0 cc :dd\r\nNICK XAXAX\r\n",
        "NICK XAXAX\r\n",
        "PASS XAXAX\r\n",
        "PASS aa\r\nPASS XAXAX\r\n",
        "PASS XAXAX\r\nUSER aa 0 cc :dd\r\n",
        "PASS XAXAX\r\nNICK XAXAX\r\nUSER XAXAX XAXAX XAXAX XAXAX\r\n",
        "PASS XAXAX\r\nSERVER aa bb cc\r\n",
        "SERVER XAXAX bb cc\r\n",
        "SERVER aa XAXAX cc\r\n",
        "SERVER aa bb XAXAX\r\n",
    );
}

sub getCommandarray {
    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    (
        "XAXAX\r\n",
        "NICK XAXAX\r\n",
        "JOIN XAXAX\r\n",
        "PART XAXAX\r\n",
        "SERVER XAXAX 1 :foobar\r\n",
        "SERVER test XAXAX :foobar\r\n",
        "SERVER test 1 :XAXAX\r\n",
        "OPER XAXAX\r\n",
        "OPER test XAXAX\r\n",
        "JOIN #XAXAX\r\n",
        "JOIN #test XAXAX\r\n",
        "JOIN \&XAXAX\r\n",
        "JOIN \&test XAXAX\r\n",
        "PART #XAXAX\r\n",
        "PART #foo XAXAX\r\n",
        "JOIN #XAXAX\r\nPART#XAXAX\r\n",
        "LIST XAXAX\r\n",
        "INVITE XAXAX #test\r\n",
        "INVITE foo #XAXAX\r\n",
        "KICK #XAXAX bar\r\n",
        "VERSION XAXAX\r\n",
        "MOTD XAXAX\r\n",
        "MODE XAXAX\r\n",
        "MODE XAXAX foo\r\n",
        "MODE foo XAXAX\r\n",
        "NAMES XAXAX\r\n",
        "STATS XAXAX\r\n",
        "STATS c XAXAX\r\n",
        "STATS h XAXAX\r\n",
        "STATS i XAXAX\r\n",
        "STATS k XAXAX\r\n",
        "STATS l XAXAX\r\n",
        "STATS m XAXAX\r\n",
        "STATS o XAXAX\r\n",
        "STATS y XAXAX\r\n",
        "STATS u XAXAX\r\n",
        "LINKS XAXAX\r\n",
        "TIME XAXAX\r\n",
        "CONNECT XAXAX\r\n",
        "TRACE XAXAX\r\n",
        "ADMIN XAXAX\r\n",
        "INFO XAXAX\r\n",
        "PRIVMSG foo XAXAX\r\n",
        "PRIVMSG XAXAX bar\r\n",
        "NOTICE foo XAXAX\r\n",
        "NOTICE XAXAX bar\r\n",
        "TOPIC XAXAX foo\r\n",
        "WHO XAXAX\r\n",
        "WHOIS XAXAX\r\n",
        "WHOWAS XAXAX\r\n",
        "WHOWAS foo 1 XAXAX\r\n",
        "KILL foo XAXAX\r\n",
        "KILL XAXAX bar\r\n",
        "PING XAXAX\r\n",
        "PONG XAXAX\r\n",
        "ERROR XAXAX\r\n",
        "AWAY XAXAX\r\n",
        "SUMMON XAXAX\r\n",
        "SUMMON foo XAXAX\r\n",
        "USERS XAXAX\r\n",
        "WALLOPS XAXAX\r\n",
        "USERHOST XAXAX\r\n",
        "ISON XAXAX\r\n"
    );
}

sub getLogin {
    ("USER aaa bbb ccc :ddd\r\n", "NICK EEEEEE\r\n");
}

sub testMisc {()}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
