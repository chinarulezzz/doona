package bedmod::dummy;

use Socket;

# Example plugin for a doona module
# Replace the use of "dummy" with your module name
# Copy the file to bedmod as <modulename.pm>

# create a new instance of this object
sub new{
    my $self = {};

    # define everything you might need
    $self->{something} = undef;

    bless $self;
    return $self;
}

# initialise some parameters
sub init{
    my $self = shift;
    my %args = @_;

    # Set protocol tcp/udp
    $self->{proto} = "tcp";

    # insert your default port here...
    $self->{port}  = $args{p} || 110;

    # verify you got everything you need, $args will provide you the
    # commandline switches from u, v, w and x

    &usage unless $args{u};

    # set info necessary for for your module..
    $self->{user} = $args{u};

    # check that the server is still alive
    die "Server failed health check!\n"
    unless $self->health_check();
}

# Perform a common action such as authenticating here
# if it this check assume it has crashed
sub health_check {
    # Should send/receive packet and match expected behaviour to be considered healthy
    # return true to continue fuzzing
    return 1;
}

# how to quit ?
sub getQuit{
    # what to send to close the connection the right way
    (
        "QUIT\r\n"
    );
}

# what to test without authenticating
# Typically the login stuff
sub getLoginarray {
    my $self = shift;
    (
        "USER XAXAX\r\n",
        "USER $self->{user}\r\nPASS XAXAX\r\n"
    );
}

# which commands does this protocol know ?
sub getCommandarray {
    my $self = shift;

    # the XAXAX will be replaced with the buffer overflow / format string data
    # place every command in this array you want to test
    (
        "foo XAXAX\r\n",
        "bar XAXAX\r\n",
        "XAXAX\r\n"
    );
}


# what to send to login ?
sub getLogin{    # login procedure
    my $self = shift;

    (
        "Hi, I am a dummy\r\n",
        "This is my pass: foobar\r\n"
    );
}

# here we can test everything besides buffer overflows and format strings
sub testMisc{
    my $self = shift;
    (
        # Insert your favourite directory traversal bug here :)
    );
}

# Module specific help goes here
# Leave an empty sub if there is no module specific help
sub usage {
    print qq~ %dummy% module specific options:
-u <description what the user should provide>

~;
}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
