#!/usr/bin/perl -w
# $Id$

# Whole huge chunks of poing.perl have been "adapted" from Net::Ping.

use strict;
use lib '../poe';
use POE;
use Socket;

# This is the default time (in seconds) to wait between ping sweeps.
my $ping_timeout = 5;

# A host must be flatlined for at least this many seconds before it is
# considered dead.  The actual amount of time is rounded up to the
# next ping timeout interval.
my $detect_host_death = 20;

# A host must not be flatlined for at least this many seconds before
# it is considered alive.  The actual amount of time is rounded up to
# the next ping timeout interval.
my $detect_host_life = 20;

# You may write ups and downs to a log file.  It's off by default.
my $log_filename = '';

#------------------------------------------------------------------------------
# Helpful functions for displaying fractions.

sub floor { my $x = int($_[0]); ($x<$_[0]) ? $x : $x-1; }

sub dec_to_fract {
  my $decimal = shift;
  my ($epsilon, $numerator, $denominator) = (5e-11, 0, 1);

  my $accumulator = $decimal;

  while (abs(floor($decimal * $denominator + 0.5) - $decimal * $denominator)
         >= $epsilon * $denominator
  ) {
    $accumulator = 1 / $accumulator;
    ($numerator, $denominator) =
      ($denominator, abs(int($accumulator)) * $denominator + $numerator);
    $accumulator = $accumulator - int($accumulator);
  }

  floor($decimal * $denominator + 0.5) . "/" . $denominator;
}

sub simplify_fract {
  my ($numerator, $denominator) = split(/\//, shift);
  my $whole = 0;

  if ($numerator >= $denominator) {
    $whole = int($numerator / $denominator);
    $numerator %= $denominator;
  }

  my @new_fract;
  push @new_fract, $whole if $whole;
  push @new_fract, join '/', $numerator, $denominator if $numerator;
  return join ' ', @new_fract;
}

#------------------------------------------------------------------------------

package POE::Component::Pinger;

use strict;
use Symbol qw(gensym);
use POE::Session;
use Socket;
use Time::HiRes qw(time);

sub _start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  $heap->{pid}       = $$ & 0xffff;
  $heap->{seq}       = 0;
  $heap->{data}      = '';
  $heap->{data_size} = length($heap->{data});

  die "icmp ping requires root privilege" if ($> and $^O ne 'VMS');

  my $protocol = (getprotobyname('icmp'))[2]
    or die "Can't get icmp protocol by name: $!";

  my $socket = gensym();
  socket($socket, PF_INET, SOCK_RAW, $protocol)
    or die "Can't create icmp socket: $!";

  $heap->{socket_handle} = $socket;
  $kernel->alias_set('pinger');
  $kernel->select_read($socket, 'got_pong');
}
                                        # ICMP echo types
sub ICMP_ECHOREPLY () { 0 }
sub ICMP_ECHO      () { 8 }
sub ICMP_STRUCT    () { 'C2 S3 A' }
sub ICMP_SUBCODE   () { 0 }
sub ICMP_FLAGS     () { 0 }
sub ICMP_PORT      () { 0 }

sub ping_clear {
  my ($heap, $address) = @_[HEAP, ARG0];
  delete $heap->{waiting}->{$address};
}

sub ping {
  my ($heap, $sender, $address, $event) = @_[HEAP, SENDER, ARG0, ARG1];

  $heap->{seq} = ($heap->{seq} + 1) % 65536;
  my $checksum = 0;
  my $msg = pack( ICMP_STRUCT . $heap->{data_size},
                  ICMP_ECHO, ICMP_SUBCODE,
                  $checksum, $heap->{pid}, $heap->{seq}, $heap->{data}
                );

  $checksum = &net_checksum($msg);

  $msg = pack( ICMP_STRUCT . $heap->{data_size},
               ICMP_ECHO, ICMP_SUBCODE,
               $checksum, $heap->{pid}, $heap->{seq}, $heap->{data}
             );

  $heap->{message_length} = length($msg);
  my $saddr = sockaddr_in(ICMP_PORT, $address);

  $heap->{waiting}->{$address} = [ $heap->{seq}, $sender, $event, time() ];

  send($heap->{socket_handle}, $msg, ICMP_FLAGS, $saddr);
}

sub got_pong {
  my ($kernel, $heap, $socket) = @_[KERNEL, HEAP, ARG0];

  my $recv_message = '';
  my $from_saddr = recv($socket, $recv_message, 1500, ICMP_FLAGS);

  return unless (defined $heap->{message_length});

  my ($from_port, $from_ip) = sockaddr_in($from_saddr);
  my ( $from_type, $from_subcode,
       $from_checksum, $from_pid, $from_seq, $from_message
     )  = unpack( ICMP_STRUCT . $heap->{data_size},
                  substr( $recv_message,
                          length($recv_message) - $heap->{message_length},
                          $heap->{message_length}
                        )
                );

  if ($from_type == ICMP_ECHOREPLY) {
    if (exists $heap->{waiting}->{$from_ip}) {
      my ($send_seq, $send_session, $send_event, $send_time) =
        @{$heap->{waiting}->{$from_ip}};
      if ($from_seq == $send_seq) {
        delete $heap->{waiting}->{$from_ip};
        $kernel->call( $send_session, $send_event,
                       $from_ip, time() - $send_time
                     );
      }
    }
  }
}

sub net_checksum {
  my $msg = shift;
  my ($len_msg,       # Length of the message
      $num_short,     # The number of short words in the message
      $short,         # One short word
      $chk            # The checksum
     );

  $len_msg = length($msg);
  $num_short = int($len_msg / 2);
  $chk = 0;
  foreach $short (unpack("S$num_short", $msg)) {
    $chk += $short;
  }                                           # Add the odd byte in
  $chk += unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
  $chk = ($chk >> 16) + ($chk & 0xffff);      # Fold high into low
  return(~(($chk >> 16) + $chk) & 0xffff);    # Again and complement
}

###############################################################################

package main;
use POE qw(Wheel::ReadWrite Driver::SysRW Filter::HTTPD Wheel::SocketFactory);

#------------------------------------------------------------------------------

sub HOST_NAME     () { 0 }
sub HOST_RESPONSE () { 1 }
sub HOST_TICKER   () { 2 }
sub HOST_DEAD     () { 3 }
sub HOST_ADDRESS  () { 4 }

# What other environment variables define the screen extent?  Assume
# 80 x 25 if nothing is availble.
my $cols = ( (exists $ENV{COLS})
             ? $ENV{COLS}
             : ( (exists $ENV{COLUMNS})
                 ? $ENV{COLUMNS}
                 : 80
               )
           ) - 3;
my $rows = ( (exists $ENV{ROWS})
             ? $ENV{ROWS}
             : ( (exists $ENV{LINES})
                 ? $ENV{LINES}
                 : 25
               )
           );

sub host_sort {
  if ($a->[1] =~ /^\d+\.\d+\.\d+\.\d+$/) {
    if ($b->[1] =~ /^\d+\.\d+\.\d+\.\d+$/) {
      # address / address compare
      return ( join('.', map { sprintf "%03d", $_ } split(/\./, $a->[1])) cmp
               join('.', map { sprintf "%03d", $_ } split(/\./, $b->[1]))
             );
    }
    else {
      return -1; # addresses come before everything
    }
  }
  else {
    if ($b->[1] =~ /^\d+\.\d+\.\d+\.\d+$/) {
      return 1; # addresses come before everything
    }
    else {
      # host / host compare (may also be aliases)
      return ( join('.', reverse(split(/\./, lc($a->[1])))) cmp
               join('.', reverse(split(/\./, lc($b->[1]))))
             );
    }
  }
}

sub pong_start {
  my ($kernel, $heap, $timeout, $hosts) = @_[KERNEL, HEAP, ARG0, ARG1];

  $heap->{timeout} = $timeout;
  $heap->{hosts} = [];
  $heap->{host_rec} = {};
  $heap->{count} = 0;

  $heap->{timeout_fraction} = &simplify_fract(&dec_to_fract($timeout / 10));
  if ($heap->{timeout_fraction} eq '1') {
    $heap->{timeout_fraction} .= ' second';
  }
  else {
    $heap->{timeout_fraction} .= ' seconds';
  }

  foreach my $host (sort host_sort @$hosts) {
    my ($ip, $hostname) = @$host;
    if (defined $ip) {
      push @{$heap->{hosts}}, $ip;
      $heap->{host_rec}->{$ip} = [ $hostname,
                                   undef,
                                   ' ' x ($cols - length($hostname)),
                                   0,
                                   inet_ntoa($ip),
                                 ];
    }
  }

  if (open LOG, ">>$log_filename") {
    my $now = gmtime(time()) . ' GMT';
    print LOG "$now\tbegin\n";
    close LOG;
  }

  my $display =
    ( "\e[2J\e[0;0H" .
      (($heap->{count} & 1) ? "\e[7m[" : '[') . "poing]\e[0m " .
      scalar(localtime(time())) .
      " (multiply numbers by " . $heap->{timeout_fraction} .
      " to get time)\n\n"
    );

  print $display;

  $kernel->yield('ping_sweep');
}

sub pong_sweep {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  $heap->{count}++;

  my $display =
    ( "\e[0;0H" .
      (($heap->{count} & 1) ? "\e[7m" : "\e[0m") . "[poing]\e[0m " .
      scalar(localtime(time())) .
      " (multiply numbers by " . $heap->{timeout_fraction} .
      " to get time)\n\n"
    );

  my (@hosts_coming_up, @hosts_going_down);
  foreach my $host (@{$heap->{hosts}}) {
    $kernel->post('pinger', 'ping', $host, 'ping_reply');

    my $host_rec = $heap->{host_rec}->{$host};

    # Remove the left end of the host ticker.
    substr($host_rec->[HOST_TICKER], 0, 1) = '';

    # Find the relative response time.
    my $relative_response =
      ( (defined $host_rec->[HOST_RESPONSE])
        ? int( ( $host_rec->[HOST_RESPONSE] / $heap->{timeout}
               ) * 10
             )
        : 10
      );

    # Clip the response to a single digit, please.
    $relative_response = ( ($relative_response > 9)
                           ? '-'
                           : ( $relative_response < 0
                               ? 0
                               : $relative_response
                             )
                         );

    # Do fun things to the display.
    my $show_health = $host_rec->[HOST_TICKER];

    # Set the initial host status so we don't get beeped immediately.
    if ($show_health =~ /^ +\S$/) {
      $host_rec->[HOST_DEAD] = ($relative_response eq '-');
    }

    $show_health .= $relative_response;
    $host_rec->[HOST_TICKER] .= $relative_response;

    if ($host_rec->[HOST_DEAD]) {
      if ($show_health =~ /[0-9]{$detect_host_life}$/) {
        push @hosts_coming_up, $host_rec;
        $host_rec->[HOST_DEAD] = !$host_rec->[HOST_DEAD];
      }
    }
    else {
      if ($show_health =~ /\-{$detect_host_death}$/) {
        push @hosts_going_down, $host_rec;
        $host_rec->[HOST_DEAD] = !$host_rec->[HOST_DEAD];
      }
    }

    my $host_is_dead = $host_rec->[HOST_DEAD];

    $show_health =~ s{(^|[^98])([98\-])}{$1\001$2}g; # red
    $show_health =~ s{(^|[^76])([76])}{$1\002$2}g; # magenta
    $show_health =~ s{(^|[^54])([54])}{$1\003$2}g; # yellow
    $show_health =~ s{(^|[^32])([32])}{$1\004$2}g; # cyan
    $show_health =~ s{(^|[^10])([10])}{$1\005$2}g; # green

    $show_health =~ s/\001/\e\[31m/g; # red
    $show_health =~ s/\002/\e\[35m/g; # magenta
    $show_health =~ s/\003/\e\[33m/g; # yellow
    $show_health =~ s/\004/\e\[36m/g; # cyan
    $show_health =~ s/\005/\e\[32m/g; # reen

    $display .=
      ( $host_is_dead
        ? "\e[0m$host_rec->[HOST_NAME]: $show_health\n"
        : "\e[0;1m$host_rec->[HOST_NAME]\e[0m: \e[1m$show_health\n"
      );

    $host_rec->[HOST_RESPONSE] = undef;
  }

  # Limit beeps to 2, please.  Ghargh!
  if (@hosts_coming_up + @hosts_going_down > 1) {
    print $display, "\a\a";
  }
  elsif (@hosts_coming_up + @hosts_going_down) {
    print $display, "\a";
  }
  else {
    print $display;
  }

  # If we're logging, log.
  if ($log_filename and (@hosts_coming_up or @hosts_going_down)) {
    if (open LOG, ">>$log_filename") {
      my $now = gmtime(time()) . ' GMT';
      foreach (@hosts_coming_up) {
        print LOG join( "\t", $now, 'up',
                        $_->[HOST_ADDRESS], $_->[HOST_NAME]
                      ), "\n";
      }
      foreach (@hosts_going_down) {
        print LOG join( "\t", $now, 'down',
                        $_->[HOST_ADDRESS], $_->[HOST_NAME]
                      ), "\n";
      }
      close LOG;
    }
  }

  # Hack to specify the maximum run time, in hours.
  if (@ARGV and ($ARGV[0] =~ /^\d*\.?\d+$/)) {
    if ((time - $^T) < ($ARGV[0] * 3600)) {
      $kernel->delay('ping_sweep', $heap->{timeout});
    }
    else {
      $SIG{ALRM} = sub { die "<<< Alarm caught >>>\n"; };
      alarm(20);
    }
  }
  else {
    $kernel->delay('ping_sweep', $heap->{timeout});
  }
}

sub pong_stop {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  foreach my $host (@{$heap->{hosts}}) {
    $kernel->post('pinger', 'ping_clear', $host);
  }

  if (open LOG, ">>$log_filename") {
    my $now = gmtime(time()) . ' GMT';
    print LOG "$now\tcease\n";
    close LOG;
  }
}

sub pong_reply {
  my ($heap, $address, $time) = @_[HEAP, ARG0, ARG1];
  $heap->{host_rec}->{$address}->[HOST_RESPONSE] = $time;
}

#------------------------------------------------------------------------------
# Load new stuff from a configuration file.

my (@hosts_to_ping, %hosts_seen);

my $poing_rc_file = $ENV{HOME};
unless (-d $poing_rc_file) {
  my $login = ( getlogin || getpwuid($<) ||
                $ENV{LOGNAME} || $ENV{LOGIN} || $ENV{USER}
              );
  $poing_rc_file = '~/' . $login;
}
die "Can't find home directory" unless -d $poing_rc_file;
$poing_rc_file .= '/.poingrc'; $poing_rc_file =~ tr[\\\/][/]s;


unless (open(HOME, "<$poing_rc_file")) {
  *HOME = *DATA;
  $poing_rc_file = 'Default poing configuration after __END__';
}

print "Loading and resolving configuration from $poing_rc_file ...\n";

while (<HOME>) {
  s/^\s+//;
  s/\s+$//;
  s/\s*\#.*//;
  s/\s+/ /g;

  next unless length;
  $_ = lc($_);

  # log filename
  if (/^log (.+?)$/) {
    $log_filename = $1;
    open LOG, ">>$log_filename" or die "Cannot append to $log_filename: $!";
    close LOG;
    next;
  }

  # host address
  if (/^host (\d+\.\d+\.\d+\.\d+)$/) {
    my $address = inet_aton($1);
    next if (exists $hosts_seen{$address});
    $hosts_seen{$address}++;
    my @name = gethostbyaddr($address, AF_INET);
    if (@name) {
      push @hosts_to_ping, [ $address, $name[0] ];
    }
    else {
      push @hosts_to_ping, [ $address, inet_ntoa($address) ];
    }
    next;
  }

  # host name
  if (/^host (\S+)$/) {
    my $address = inet_aton($1);
    if (defined $address) {
      next if (exists $hosts_seen{$address});
      $hosts_seen{$address}++;
      push @hosts_to_ping, [ $address, $1 ];
    }
    else {
      warn "Cannot resolve host name from line $. of $poing_rc_file\n";
    }
    next;
  }

  # host address and name
  if (/^host (\S+) (.+?)$/) {
    my $address = inet_aton($1);
    if (defined $address) {
      next if (exists $hosts_seen{$address});
      $hosts_seen{$address}++;
      push @hosts_to_ping, [ $address, $2 ];
    }
    next;
  }

  if (/^ping_timeout (\d+\.\d+|\.\d+|\d+\.|\d+)$/) {
    if ($1) {
      $ping_timeout = $1;
    }
    else {
      warn "Ping timeout may not be zero at $poing_rc_file line $.\n";
      warn "Setting ping timeout to 1/100 second at $poing_rc_file line $.\n";
      $ping_timeout = 0.01;
    }
    next;
  }

  if (/^detect_host_death (\d+)$/) {
    $detect_host_death = $1;
    next;
  }

  if (/^detect_host_life (\d+)$/) {
    $detect_host_life = $1;
    next;
  }

  warn "Bad poing configuration on line $. of $poing_rc_file\n";
}
close HOME;
close DATA;

#------------------------------------------------------------------------------
# Preprocess the detection times.

$detect_host_death /= $ping_timeout;
$detect_host_death = int($detect_host_death) + 1
  if ($detect_host_death =~ /\./);

$detect_host_life /= $ping_timeout;
$detect_host_life = int($detect_host_life) + 1
  if ($detect_host_life =~ /\./);

#------------------------------------------------------------------------------

create POE::Session
  ( package_states =>
    [ 'POE::Component::Pinger' => [ qw(_start ping got_pong ping_clear) ],
    ],
  );

create POE::Session
  ( inline_states =>
    { _start     => \&pong_start,
      _stop      => \&pong_stop,
      ping_reply => \&pong_reply,
      ping_sweep => \&pong_sweep,
    },
    args => [ $ping_timeout, \@hosts_to_ping ],
  );

$poe_kernel->run();

exit;

__END__

# Sample sites.

host 208.60.68.29    www.memepool.com
host 199.245.105.172 www.infobot.org
host 204.152.190.11  altavista.com
host 209.197.104.63  www.sluggy.com
