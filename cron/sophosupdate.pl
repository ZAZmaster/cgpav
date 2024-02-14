#!/usr/bin/perl -T

# This is sophos-update.pl .
# Its purpose is to update virus signature .ide files
# from the Sophos web server.
#
# Copyright (C) 2001  Mark Martinec,  All Rights Reserved.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Mark Martinec <mark.martinec@ijs.si>
# Patches and problem reports are welcome.
# Other licensing terms are possible, please contact the author.
#
# The latest version of this program is available at:
#   http://www.ijs.si/software/sophos-ide-update/

#==============================================================================
# This is the sequence of steps the program goes through:
# - creates a temporary directory as a working area and as a locking mechanism;
# - sends a conditional HTTP GET request to a Sophos' web server
#   requesting <x>_ides.zip file if and only if it is younger
#   than the local copy;
# - downloads the new <x>_ides.zip file (if younger) into a temporary directory
#   and unpacks it flatly, ignoring paths and members with weird names;
# - compares the current and new .ide files, decides what changes need
#   to be made, carefully updates the 'sav' directory and produces a report;
# - if Sophie daemon is detected and any changes were made, send it a SIGHUP;
# - writes a terse report to a log file (if defined) and mails it (or a
#   possible problem report) to an administrator (if specified);
# - removes the temporary directory;
# - exits with code 0 (success) if:
#    * everything went smoothly,
#    * or, there was a problem, but a problem report was successfully mailed;
#    * or, regardless of any problems, a '-s' command line option was set
#      (useful to prevent mail bounces if the program is run from a MTA pipe);
#   otherwise exit code is nonzero;
#
# This program can be run periodically (e.g. from cron), or/and triggered
# on-demand by some other means, e.g. manually or run by MTA using an alias
# that pipes Sophos IDE update announcements to it (actual message on stdin
# is ignored, MTA pipe delivery is used only as a trigger).
#
# NOTE:
#   To force a zip archive reload, and a re-check of all the ide files,
#   simply remove the zip archive from the local 'sav' directory,
#   or set its modification time to and old date (e.g. with 'touch').
# WARNING:
#   The local zip file modification timestamp (POSIX/UTC time) is compared
#   to the timestamp of the file at the Sophos' web server to decide
#   whether an update is needed or not - file contents is not compared!
#   Never set this timestamp to a later date or you risk missing an update
#   (i.e. watch how you move or backup/restore file systems).

# The following access rights are required:
# - read and write access to the local 'sav' directory;
# - web access (HTTP GET requests, possibly through a proxy);
# - with Sophie: a right to send SIGHUP to a Sophie daemon,
#   and a way to get its PID, either by reading /var/run/sophie.pid
#   or by calling 'lsof' (see below) - each may require root privileges.
#
# This either calls for running the program as root, which is not nice,
# but probably not too dangerous, and it is a good thing(tm) if local 'sav'
# directory and IDE files are owned by root; also makes it easy to find
# and to send a signal to the Sophie daemon. The downside is that MTA
# normally (and with a good reason) refuses to run a delivery pipe as root,
# so this limits you to periodic updates from cron.
#
# Alternatively, run it as an owner of the local 'sav' directory and IDE files
# in it, which, to be doubly sure, can be different from the UID of the
# amavisd processes to prevent it from accidentally modifying them.
# If MTA pipe is used as a trigger, make sure the process runs
# with the desired UID. To be able to signal Sophie, its UID must also
# be the same.
#
# To my taste the ideal combination would be:
# - running this program periodically from cron, e.g. every couple of hours;
# - triggering it also from MTA via alias pipe when an update notification
#   from Sophos is received. Pipe and cron jobs should run under the same UID.

# If you run into trouble (or the first time you do it), run this program
# in verbose mode: give it a command line option '-v' or '-v -v' .


#==============================================================================
# 2001-10	Mark Martinec <mark.martinec@ijs.si>
#   - initial version
# 2001-11	Mark Martinec
#   - added extensive error checking, reporting and signal trapping;
#   - use (and restore) Unix/POSIX timestamps in the ZIP archive if available;
# 2001-11-08	Mark Martinec
#   - make directory merge a two-stage process:
#     first decide what needs to be done, then do the update;
#   - parse /etc/sav.conf (if present) for the location
#     of the virus signatures directory;
#   - cleanup
# 2001-11-23	Mark Martinec
#   - return success even when fatal error is detected
#     but reported by mail successfully;
#   - signal reload to a Sophie daemon if found;
# 2001-11-27	Mark Martinec
#   - more detailed documentation, further refinement (e.g. lsof_search)
# 2001-12-04	Mark Martinec
#   - final polishing;
#   - first public release 1.0
#==============================================================================

  $ENV{'PATH'} = '';
  use strict;

  use POSIX;
  use IO::File;
  use File::Basename;
  use HTTP::Headers;
  use HTTP::Status;
  use LWP::UserAgent;
  use Archive::Zip qw( :ERROR_CODES :CONSTANTS );

  use vars qw(
    $urldir $zipfile_fmt $lstfile_fmt
    $savdir $tmpdir $sav_version_maj $sav_version_min
    $verbose $neverfail $valid_ide_name_patt
    $ua_agent_name $log_filename @logentry
    $mail_from $mail_to $mail_subj
    $sophie_pidfile $sophie_socket $lsof_path
  );


#==============================================================================
# Main configuration settings:
#==============================================================================

# URL of a directory at the Sophos web server,
# where an up-to-date version of the zip archive is maintained:
#
  $urldir = 'http://www.sophos.com/downloads/ide';       # (no trailing slash!)

# sprintf format string to assemble remote file names. Two parameters 
# supplied to sprintf will be Sophos SAV major and minor version numbers.
# "$urldir/" will be prepended to form a full URL.
#
  $zipfile_fmt = '%d%d_ides.zip';   # remote zip file name
  $lstfile_fmt = '%d%d_list.txt';   # (not used)

# $tmpdir is a directory used by this program as a temporary storage
# to download new zip archive and to unpack it. It must reside on the
# same file system as $savdir, hard link tricks and renames are used
# to safely and atomically update $savdir at the final stage.
# $tmpdir may be (but need not be) a subdirectory of $savdir .
# The directory and its contents is created and destroyed by this program.
# The directory must not exist at the time the program is invoked,
# or else it would assume another instance of itself is already active
# and would exit. (Btw, 'current working directory' of the process does not
# matter, but it is probably not a good idea to let it be a nfs-mounted fs.)
#
# "$savdir/" will be prepended to $tmpdir if it does not start with a "/" .
#
  $tmpdir = 'sav-new-tmp';                               # (no trailing slash!)
# $tmpdir = '/usr/local/sav-new-tmp';                    # (no trailing slash!)

# If $log_filename is defined, this file will collect the short one-line
# status reports of each run, along with local timezone timestamps (ISO 8601).
# "$savdir/" will be prepended to $log_filename if it does not start with a "/"
#
  $log_filename = '000last_updated.log';
# $log_filename = '/var/log/000last_updated.log';

# Check also the procedure get_sophos_data_directory() further down
# if you keep both the /etc/sav.conf and /usr/local/sav in other locations.


#==============================================================================
# Mail reporting section:
#==============================================================================

# From:, To: and Subject: fields for mail notifications,
# reporting interesting updates, or problems.
#
# If $mail_to is left undefined, no mail reports will be sent.
# If $mail_from is left undefined, let the local mail system
# determine the sender address. Missing domain names will hopefully
# be provided by MTA.

  $mail_subj = 'IDE-update report';
  $mail_from = 'virusupdates';
  $mail_to   = 'postmaster';

# $mail_to   = 'virusalert@your.domain';

# If the program is invoked with any command-line arguments, they are
# cleaned for nonprintable characters and appended to $mail_subj,
# which can be used to distinguish between cron-activated and MTA
# pipe-activated runs.

#==============================================================================
# Sophie section:
#==============================================================================

# If using Sophie (http://www.vanja.com/tools/) for checking viruses
# instead of the traditional Sophos 'sweep' utility, this program will
# attempt to cause the Sophie daemon to reload its virus signatures
# (by sending it a SIGHUP signal) if any changes in the ide files
# are made. For this it needs to know a process id of the Sophie daemon,
# and it will need to be able to send it a signal, so it must either
# run as root or under the same UID as Sophie (which is likely to be
# root as well, so you don't have a choice).

# If Sophie is not used, these variables may be left undefined to avoid
# pid-finding attempts, but it does not hurt to keep the defaults
# as absent Sophie socket file will prevent 'lsof' runs.
# For details see get_sophie_pid() further down.
#
# Either: existing $sophie_pidfile, or
# existing Unix socket $sophie_socket together with a working 'lsof'
# (at $lsof_path) will suffice to find Sophie daemon.
# If both the file, and the lsof are present, lsof will be used
# to check the validity of pid as read from the $sophie_pidfile.

# $sophie_pidfile should be a file name to which Sophie daemon
# writes its process id (supposedly since Sophie V1.17, although
# not in sophie-1.20a1). It does not hurt if the file does not exist.
#
  $sophie_pidfile = '/var/run/sophie.pid';

# $sophie_socket is a Unix socket name which Sophie daemon keeps open.
# Must be an absolute path. 'lsof' (if available) will try to locate
# a parent process (i.e. Sophie children will be ignored) which has
# this socket open and runs a command named 'sophie'.
#
  $sophie_socket = '/var/run/sophie';

# Full path of the 'lsof' program.
# In case you do not have it, home of lsof is at:
#   ftp://vic.cc.purdue.edu/pub/tools/unix/lsof
#
  $lsof_path = '/usr/local/bin/lsof';

# Comment out the $lsof_path or $sophie_socket if you want to prevent
# 'lsof' to be called regardless of the existence of Sophie socket file.

# NOTE:
#   I prefer locating a Sophie daemon using 'lsof' (over the 'ps')
#   because lsof checks for actually open socket, makes it easier to
#   distinguish parent from children, and is harder to be misled
#   by some other process which happen to use the same command name;
#   not to mention that 'ps' option syntax differs between Unix variants.


# HOPEFULLY NO FURTHER USER-CONFIGURABLE SETTINGS BELOW
#==============================================================================


# used to identify this program in HTTP requests and mail reports:
  $ua_agent_name = 'sophos-ide-update/1.0';

# to be extra cautious, valid name for .ide files must match this pattern:
  $valid_ide_name_patt = '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,1019}\.ide$';



# Get Sophos AV version number currently in use on this system.
#
# Do it by parsing soft link vld.dat, although a more correct (but also
# more risky and slow) way would be to run 'sweep' and parse its output.
#
sub get_sophos_version {
  if (-l "$savdir/vdl.dat") {
    my($vdl) = readlink("$savdir/vdl.dat")
                 or die "Can't read symbolic link <$savdir/vdl.dat>: $!";
    return ($1,$2)  if $vdl =~ /\bvdl-(\d+)\.(\d+)\.dat$/;
  }
  undef;
}

# Get Sophos AV virus signatures directory.
#
sub get_sophos_data_directory {
  my($configfile)     = '/etc/sav.conf';
  my($savdir_default) = '/usr/local/sav';
  my($savdir);
  if (-f $configfile) {
    open(C, $configfile)
      or die "Can't open file <$configfile> for reading: $!";
    while (<C>) {
      chomp;
      if (m'^SAV virus data directory\s*=\s*(\S+)\s*$'i) { $savdir = $1; last }
    }
    close(C) or die "Can't close file <$configfile>: $!"
  }
  if (defined($savdir)) {
    printf("Virus data directory (specified in the config file <%s>): %s\n",
           $configfile, printable($savdir))  if $verbose >= 2;
  } else {
    $savdir = $savdir_default;
    printf("Using default virus data directory: %s\n",
           printable($savdir))  if $verbose >= 2;
  }
  chop($savdir) if $savdir =~ m(/$);
  return (-d $savdir) ? $savdir : undef;
}

# Look for certain processes by running 'lsof' (a command to list open files).
# Compiles a list of process IDs that match search options.
# From the compiled list extract only process group leaders
# and return that list. Each process id can occur only once in the list.
# Home of lsof is: ftp://vic.cc.purdue.edu/pub/tools/unix/lsof
# in case your system does not already have it installed.
#
sub lsof_search {
  my($exact_command_name,  # process command name to limit the search, or undef
     $command_options_ref, # a ref to a list of lsof options    (may be undef)
     $command_args_ref,    # a ref to a list of lsof parameters (may be undef)
    ) = @_;
  my(@command) = ($lsof_path, '-FpgRcu');
  push(@command, @$command_options_ref)     if ref $command_options_ref;
  push(@command, '-c', $exact_command_name) if defined $exact_command_name;
  push(@command, '--', @$command_args_ref)
       if ref($command_args_ref) && @$command_args_ref;
  my($command) = join(' ',@command);
  printf("running command: %s\n", $command)  if $verbose >= 2;
  $| = 1;  # make STDOUT unbuffered before forking to avoid duplicates
  my(@unique_pids);
  my($lsof_pid); my($sleep_count) = 0;
  do {     # fork a child process that will exec 'lsof'
    $lsof_pid = open(LSOF_PROC, "-|");
    if (!defined($lsof_pid)) {
      die "Can not fork a process to run 'lsof': $!"  if $sleep_count++ > 6;
      sleep 5;
    }
  } until defined($lsof_pid);
  if (!$lsof_pid) {   # child
    open(STDERR, '>/dev/null');  # lsof complains to stderr if unable
                                 # to find what is being looked for
    exec(@command) or die "Can't exec: <$command>: $!";
    # NOTREACHED
  } else {      # parent
    my($pid,$pgid,$ppid,$cmd); my(%parent,%pgid);
    while (<LSOF_PROC>) {
      chomp;
      printf("%slsof output: %s\n", (/^p/?"\n":""), $_)  if $verbose >= 2;
      if (/^p/ && defined($pid)) { # new process, save the previous one
        # the complication with $exact_command_name is needed because
        # the -c parameter matches any command that _starts_ with this string
        if (!defined($exact_command_name) || $cmd eq $exact_command_name) {
          $pgid{$pid}   = $pgid  if defined $pgid;
          $parent{$pid} = $ppid  if defined $ppid;
          $pid = $pgid = $ppid = $cmd = undef;
        }
      }
      $pid  = $1  if /^p(\d+)$/;  # process id
      $pgid = $1  if /^g(\d+)$/;  # process group id
      $ppid = $1  if /^R(\d+)$/;  # parent process id
      $cmd  = $1  if /^c(.*)$/;   # command name
    }
    if (defined($pid)) {  # do the last one
      if (!defined($exact_command_name) || $cmd eq $exact_command_name) {
        $pgid{$pid}   = $pgid  if defined $pgid;
        $parent{$pid} = $ppid  if defined $ppid;
      }
    }
    if (!close(LSOF_PROC)) {
      my($msg) = "'lsof' failed with (composite) status $?";
      printf("%s\n", $msg) if $verbose >= 1;
      push(@logentry, $msg);
    }
    my(@pids) = keys(%parent);
  # replace pids in the list with their ultimate ancestor
    for my $pid (@pids) {
      while (exists $parent{$pid} && exists $parent{$parent{$pid}}) {
        my($ppid) = $parent{$pid};
        last if $pid == $ppid;   # break loop in case we stumbled on the kernel
        last if $pgid{$pid} != $pgid{$ppid};  # stay within the same proc group
#       last if $ppid == 1;      # not interested in the init process
        printf("lsof_search: %d -> %d\n", $pid,$ppid) if $verbose >= 2;
        $pid = $ppid;  # modifies the element in the list, not its copy
      }
    }
    for my $pid (@pids) {  # uniq
      push(@unique_pids, $pid)  unless grep {$_ == $pid} @unique_pids;
    }
  }
  printf("lsof_search found processes: %s\n",
         join(", ",@unique_pids))  if $verbose >= 1;
  return wantarray ? @unique_pids : join(' ',@unique_pids);
}

# Try to get process id of a Sophie daemon.
# Return its pid, or undef in case Sophie is not found.
# Dies in certain cases if attempt fails (like if Sophie pid file
# exists but is unreadable by this process, or if unable to fork
# and run lsof).
#
sub get_sophie_pid {
  my($sophie_pid);
  if (defined($sophie_pidfile) && -f($sophie_pidfile)) {   # since Sophie V1.17
    open(PID_FILE, "<$sophie_pidfile")
      or die "Can't read file <$sophie_pidfile>: $!";
    while (<PID_FILE>) { chomp; $sophie_pid = $1 if /^(\d+)$/ }
    close(PID_FILE) or die "Can't close file <$sophie_pidfile>: $!";
    if (defined($sophie_pid)) {
      printf("Got Sophie PID [%s] from file <%s>\n",
             $sophie_pid, $sophie_pidfile)  if $verbose >= 2;
    }
  }
  if (!defined($lsof_path) || !-x($lsof_path)) {
    printf("No executable lsof at <%s>, not calling it\n",
           $lsof_path)  if $verbose >= 2;
  } elsif (!defined($sophie_socket) || !-S($sophie_socket)) {
    printf("No Sophie socket: <%s>, not calling lsof\n",
           $sophie_socket)  if $verbose >= 2;
  } else {
    # Try to obtain Sophie parent daemon's process id by running 'lsof',
    # asking it to look for a process group leaders running a command 'sophie'
    # and having open a Unix socket named $sophie_socket .
    my(@pids) = lsof_search('sophie', ['-a', '-U'], [$sophie_socket]);
    my($actual_sophie_pid);
    if (@pids == 1) {
      $actual_sophie_pid = $pids[0];
      printf("Got Sophie PID [%s] by running 'lsof'\n",
             $actual_sophie_pid)  if $verbose >= 2;
    } elsif (@pids > 1) {
      my($msg) = 'More than one Sophie family running!? [pids:' .
                 join(',',@pids) . ']';
      printf("%s\n", $msg) if $verbose >= 1;
      push(@logentry, $msg);
    }
    if (defined($sophie_pid) && defined($actual_sophie_pid)) {
      if ($sophie_pid == $actual_sophie_pid) {
        # very good!
      } else {
        printf("Sophie PID [%s] as read from the file <%s>, " .
               "and the one found by 'lsof' [%s] differ, using later\n",
               $sophie_pid, $sophie_pidfile, $actual_sophie_pid
              )  if $verbose >= 1;
        push(@logentry,
             "Which Sophie PID: $sophie_pid or $actual_sophie_pid? Using the later.");
      }
    }
    $sophie_pid = $actual_sophie_pid  if $actual_sophie_pid;
  }
  $sophie_pid;
}

# Try to obtain PID of a Sophie daemon
# and send SIGHUP to it if found, causing virus signatures to be reloaded.
#
sub reload_sophie {
  my($success);
  my($sophie_pid) = get_sophie_pid();
  if (!$sophie_pid) {
    printf("No Sophie daemon detected\n")  if $verbose >= 2;
    push(@logentry, "No Sophie");
  } elsif (!kill(1,$sophie_pid)) {   # send SIGHUP to Sophie daemon
    my($msg) = "Can't SIGHUP Sophie[$sophie_pid]: $!";
    printf("%s\n", $msg)  if $verbose >= 1;
    push(@logentry, $msg);
  } else {
    my($msg) = "SIGHUP sent to Sophie[$sophie_pid]";
    printf("%s\n", $msg)  if $verbose >= 1;
    push(@logentry, $msg);
    $success = 1;
  };
  $success;
}

# Get a document from a web server and atomically save it to a file
# (relying on atomicity of file system directory operations).
#
# Download only if necessary: if modification time (e.g. of the
# existing file) is known, send it in the conditional GET request
# ("If-Modified-Since" header).
#
# If "Last-Modified" timestamp is available in the HTTP response,
# use it to set the file modification time of a freshly transferred file.
# File will only be created (and left undeleted) after an actual
# and successful download.
#
# Throws an exception on error (but _not_ in case of 404 NOT_FOUND),
# otherwise:
#   returns RC_OK           if file was successfully downloaded;
#   returns RC_NOT_MODIFIED if file need not be refreshed according to
#                             timestamps; no new file is downloaded;
#   returns RC_NOT_FOUND    if the document does not exist on the
#                             web server (status 404), which is a valid
#                             condition when no .ide files exist for
#                             a given Sophos SAV version.
#
sub get_document {
  my($url, $filename, $ref_time, $size_limit) = @_;
  my($tmpfile) = $filename . '.tmp';
  my($size) = 0;

  my($ua) = new LWP::UserAgent;
  $ua->agent($ua_agent_name . ' ' . $ua->agent);
  $ua->timeout(5*60);         # 5 minutes timeout for a GET request
# $ua->env_proxy;

  my($req) = new HTTP::Request('GET',$url);
  $req->header("Pragma", "no-cache");
  $req->if_modified_since($ref_time) if defined $ref_time;
# printf("HTTP request: <%s>\n", $req->as_string())  if $verbose >= 2;
  open(FILE, ">$tmpfile") or die "Can't create file <$tmpfile>: $!";
  binmode FILE  if $filename =~ /\.(zip|gz|bz2|Z|tar|bin|exe)$/; # simpleminded
  my($res) = $ua->request(
              $req,
              sub {
                print FILE $_[0] or die "Can't write to file <$tmpfile>: $!";
                $size += length($_[0]);
                if (defined($size_limit) && $size > $size_limit) {
                  $! = 1; die "Exceeded size limit ($size > $size_limit)";
                }
              },
              32*1024
            );
  close(FILE) or die "Can't close temporary file <$tmpfile>: $!";

  my($status_code) = $res->code;
  if (!$res->is_success) {
    if (-f $tmpfile) {  # may or may not exist
      unlink($tmpfile) or die "Can't remove file <$tmpfile>: $!";
    }
    if ($status_code == RC_NOT_FOUND || $status_code == RC_NOT_MODIFIED) {
      # these two status codes are expected; don't die, just return status code
    } else {
      my($status) = $res->status_line;  chomp($status);
      $! = 1;  die "Web transfer failed: $status\n";
    }
  } elsif ($res->header("X-Died")) {  # die called from the callback routine
    if (-f $tmpfile) {  # may or may not exist
      unlink($tmpfile) or die "Can't remove file <$tmpfile>: $!";
    }
    my($stat) = $res->header("X-Died"); chomp($stat);
    $! = 1;  die "Web transfer failed (X-Died): $stat\n";
  } else {  # success
    my($content_length) = $req->content_length;
    if (defined($content_length)) {
      my($file_length);
      my(@stat) = stat($tmpfile);
      if (!@stat) { die "Can't stat() file <$tmpfile>: $!" }
      else { $file_length = $stat[7] }
      if ($file_length < $content_length) {
        unlink($tmpfile) or die "Transfer truncated; can't remove file <$tmpfile>: $!";
        $! = 1; die "Web transfer truncated: " .
                    "only $file_length out of $content_length bytes received";
      } elsif ($file_length > $content_length) {
        unlink($tmpfile)
          or die "Content-length mismatch; can't remove file <$tmpfile>: $!";
        $! = 1; die "Content-length mismatch: " .
                    "expected $content_length bytes, got $file_length";
      }
    }
    my($last_modified_time) = $res->last_modified;
    if (!$last_modified_time) { $last_modified_time = undef }
    elsif ($last_modified_time > time+5*60) {
      $last_modified_time = undef;  # time too far in the future
      my($msg) = sprintf("Zip timestamp in the future (%s UTC), ignored! ".
                         "Check your clock and time zone!",
                         scalar(gmtime($last_modified_time)));
      printf("%s\n", $msg) if $verbose >= 1;
      push(@logentry, $msg);
    }
    if (!defined($last_modified_time)) {
      push(@logentry, "Zip timestamp not set!");
    } else {
      utime(time, $last_modified_time, $tmpfile)
        or die "Can't set modification timestamp on file <$tmpfile>: $!";
    }
    rename($tmpfile,$filename)
      or die "Can't rename file <$tmpfile> to <$filename>: $!";
    $status_code = RC_OK;
  }
  $status_code;
}

# Send a report by e-mail, but only if recipient is defined.
# Dies if sending mail fails.
#
sub send_mail {
  my($from,$to,$subj,$content) = @_;
  return undef  if !defined($to);
  $content =~ s/[\r\n]*$/\n/s;  # assure exactly one trailing newline
  my($ua) = new LWP::UserAgent;
  $ua->agent($ua_agent_name . ' ' . $ua->agent);
  my($req) = new HTTP::Request('POST', "mailto:$to");  # URI encode???
  $req->from($from)               if defined $from;
  $req->header('Subject', $subj)  if defined $subj;
  $req->content($content)         if defined $content;
  my($res) = $ua->request($req);
  if (!$res->is_success) {
    my($status) = $res->status_line; chomp($status);
    die "Failed to send mail to <$to>: $status ($!)";
  }
  1;
}

# Get modtime from the Unix timestamp in a zip archive
# if available as an 'extra field'.
# (Code by Ned Konz, the author of Archive::Zip - Thanks!)
#
sub get_zipmember_mtime {
  my($member) = @_;
  my($eas) = $member->extraFields();
#   Bytes 0-1 'UT' (0x5455)
#   Bytes 2-3 field length, little-endian (1, 5, 9, or 13)
#   Byte 4 flags byte:
#     bit 0 mtime present
#     bit 1 atime present
#     bit 2 ctime present
#     times are given in above order (mtime/atime/ctime)
#   byte 5-8 first time, if present (Unix/POSIX time (almost UTC))
#   byte 9-12 second time, if present
#   byte 13-16 third time if present
  my($mtime,$atime,$ctime);
  while (length($eas)) {    # for each EA
    my($type,$length) = unpack("vv", $eas);
    my($body) = substr($eas, 4, $length);
#   printf "--\nEA Type: 0x%04x Length: %d\n", $type, $length;
    if ($type == 0x5455) {  # EF_TIME 'UT'
      my($format) = 'CV' . int(($length-1)/4);
      my($flags, @fields) = unpack($format, $body);
#     printf "UT format: %s flags: %x\n", $format, $flags;
      my($time) = 0;
      if ($flags & 1) {
        $time = shift(@fields) || $time;
        $mtime = $time;
      }
      if ($flags & 2) {
        $time = shift(@fields) || $time;
        $atime = $time;
      }
      if ($flags & 4) {
        $time = shift(@fields) || $time;
        $ctime = $time;
      }
    }
    $eas = substr($eas, 4+$length);
  }
  return !wantarray ? $mtime : ($mtime,$atime,$ctime);
}

# Unpack a zip archive (ignoring pathnames and overriding file mods,
# but keeping last modification times of archive members if available)
#
sub unzip {
  my($zipfilename,$dstdir,$patt) = @_;
  my($zip) = Archive::Zip->new();
  $zip->read($zipfilename) == AZ_OK
    or die "Error reading zip archive <$zipfilename>: $!";
  File::Basename::fileparse_set_fstype('UNIX'); # must match the Sophos
                                    # archive type, not the local architecture!
  my($fh) = new IO::File;
  for my $member ($zip->members()) {
    my($name) = $member->fileName();
    my($basename) = basename($name);
    if ($basename !~ /($patt)/) {
      printf("Ignoring archive member <%s>, base name <%s> does not match pattern\n",
             printable($name), printable($basename))  if $verbose >= 1;
      push(@logentry,
           sprintf("Ignoring archive member <%s>, please investigate.",
                    printable($name)));
    } else {
      $basename = $1;  # untaint after checking
      $fh->open("$dstdir/$basename", "w")
        or die "Can't create file <$dstdir/$basename>: $!";
      chmod(0644, "$dstdir/$basename")   # -rw-r--r--
        or die "Can't chmod file <$dstdir/$basename> to 0644: $!";
    # $fh->binmode()  if $member->isBinaryFile; # overruled by writeToFileHandle anyway
      $member->extractToFileHandle($fh) == AZ_OK
        or die "Error extracting member <$name> from the zip archive ".
               "to file <$dstdir/$basename>: $!";
      $fh->close or die "Can't close file <$dstdir/$basename>: $!";
      my($t) = get_zipmember_mtime($member);  # get UTC modif.time if available
      if (!defined($t)) {   # take member's local time as an approximation
        $t = $member->lastModTime();
        # NOTE: if we came here we are clueless about true timestamps
        # and can only hope the creator's and reader's time zones are the same.
        # As a fudge one may manually supply offset between the two time zones.
        # Luckily it seems Sophos' zip archive contains Unix timestamps.
      };
      if ($t =~ /^(\d+)$/) {
        $t = $1;   # untaint and check for sanity
        if ($t && $t < time+5*60) {       # ignore if too far in the future
          utime(time, $t, "$dstdir/$basename")
            or die "Can't set modification timestamp on file <$dstdir/$basename>: $!";
        }
      }
    }
  }
}

# Binary compare files.
# Returns true if files are the same or equal,
# return false if files are different,
#
sub files_are_equal {
  my($filename1,$filename2) = @_;
  my(@stat1) = stat($filename1);
  my(@stat2) = stat($filename2);
  my($dev1,$ino1,$mode1,$nlink1,$uid1,$gid1,$rdev1,$size1,
     $atime1,$mtime1,$ctime1,$blksize1,$blocks1);
  my($dev2,$ino2,$mode2,$nlink2,$uid2,$gid2,$rdev2,$size2,
     $atime2,$mtime2,$ctime2,$blksize2,$blocks2);
  if (!@stat1) { die "Can't stat() file <$filename1>: $!" }
  else { ($dev1,$ino1,$mode1,$nlink1,$uid1,$gid1,$rdev1,$size1,
          $atime1,$mtime1,$ctime1,$blksize1,$blocks1) = @stat1;
  }
  if (!@stat2) { die "Can't stat() file <$filename2>: $!" }
  else { ($dev2,$ino2,$mode2,$nlink2,$uid2,$gid2,$rdev2,$size2,
          $atime2,$mtime2,$ctime2,$blksize2,$blocks2) = @stat2;
  }
  my($equal);
  if ($size1 != $size2) {
    $equal = 0;  # different sizes, no need to go through contents
  } elsif ($dev1 == $dev2 && $ino1 == $ino2) {
    $equal = 1;  # same file, no need to go through contents
  } else {
    $equal = 1;
    open(OF, $filename1) or die "Can't open file <$filename1> for reading: $!";
    open(NF, $filename2) or die "Can't open file <$filename2> for reading: $!";
    # binary compare
    for (;;) {
      my($str1,$str2);
      my($n1) = read(OF,$str1,1024*8);
      my($n2) = read(NF,$str2,1024*8);
      if (!defined($n1)) {
        die "Can't read from <$filename1>: $!"; last;
      } elsif (!defined($n2)) {
        die "Can't read from <$filename2>: $!"; last;
      } elsif (!$n1 && !$n2) {
        last;  # end of file on both files at the same time
      } elsif ($n1 != $n2 || $str1 ne $str2) {
        $equal = 0; last;
      }
    }
    close(OF); close(NF);
  }
  $equal;
}

# Compare current and new directories containing .ide file.
# Carefully modify old directory to refect new picture
# using hard links and renames. No copying is done,
# both directories must reside on the same filesystem.
# Relies on atomicity of directory updates, ensured by file system.
#
sub merge_dir {
  my($savdir,$newdir) = @_;
  my(@retired, @newentries, @changed);

# get a list of .ide files for matching
  opendir(SAVDIR, $savdir) or die "Can't open directory <$savdir>: $!";
  my(@origlist) = sort grep { /$valid_ide_name_patt/o && -f "$savdir/$_" }
                            readdir(SAVDIR);
  closedir(SAVDIR);
  map {/($valid_ide_name_patt)/o; $_ = $1} @origlist; # untaint after checking

  opendir(NEWDIR, $newdir) or die "Can't open directory <$newdir>: $!";
  my(@newlist)  = sort grep { /$valid_ide_name_patt/o && -f "$newdir/$_"  }
                            readdir(NEWDIR);
  closedir(NEWDIR);
  map {/($valid_ide_name_patt)/o; $_ = $1} @newlist;  # untaint after checking

# merge sorted directory names
# and produce lists: @retired, @newentries, @changed
#
  my($origf,$newf);
  $origf = shift(@origlist)  if @origlist > 0;
  $newf  = shift(@newlist)   if @newlist  > 0;
  while (defined($origf) && defined($newf)) {
    if ($newf gt $origf) {       # removed $origf
      push(@retired, $origf);   $origf = shift(@origlist);
    } elsif ($origf gt $newf) {  # new file $newsf
      push(@newentries, $newf); $newf = shift(@newlist);
    } else {    # $origf eq $newf
      # Old and new file with the same name are present. Are they equal?
      if (files_are_equal("$savdir/$origf", "$newdir/$newf") ) {
        print "unchanged: $newf\n"  if $verbose >= 2;
      } else {
        push(@changed, $newf);
      }
      ($origf,$newf) = (shift(@origlist), shift(@newlist));
    }
  }
  while (defined($origf)) {
    push(@retired, $origf); $origf = shift(@origlist);
  }
  while (defined($newf)) {
    push(@newentries, $newf); $newf = shift(@newlist);
  }

# Update directory $savdir according to lists @retired, @newentries, @changed.
# A filename can not be in more than one of these lists.
#
  for my $f (@newentries) {
    print "new file $f\n"  if $verbose >= 1;
    link("$newdir/$f", "$savdir/$f")
      or die "Can't copy(link) <$newdir/$f> to <$savdir/$f>: $!";
    if (-f "$savdir/$f-retired") {
      print "  info: $f was once retired and is now present again\n"  if $verbose >= 1;
      unlink("$savdir/$f-retired")
        or die "Can't remove file <$savdir/$f-retired>: $!";
    }
    if (-f "$savdir/$f-superseded") {
      unlink("$savdir/$f-superseded")
        or die "Can't remove file <$savdir/$f-superseded>: $!";
    }
  }
  for my $f (@changed) {
    print "changed: $f\n"  if $verbose >= 1;
    if (-f "$savdir/$f-superseded") {
      unlink("$savdir/$f-superseded")
        or die "Can't remove file <$savdir/$f-superseded>: $!";
    }
    rename("$savdir/$f", "$savdir/$f-superseded")
      or die "Can't rename <$savdir/$f> to <$savdir/$f-superseded>: $!";
    link("$newdir/$f", "$savdir/$f")
      or die "Can't copy(link) <$newdir/$f> to <$savdir/$f>: $!";
  }
  for my $f (@retired) {
    print "retired $f\n"  if $verbose >= 1;
    if (-f "$savdir/$f-retired") {
      unlink("$savdir/$f-retired")
        or die "Can't remove file <$savdir/$f-retired>: $!";
    }
    rename("$savdir/$f", "$savdir/$f-retired")
      or die "Can't rename <$savdir/$f> to <$savdir/$f-retired>: $!";
    if (-f "$savdir/$f-superseded") {
      unlink("$savdir/$f-superseded")
        or die "Can't remove file <$savdir/$f-superseded>: $!";
    }
  }
  push(@logentry, "RETIRED: ".join(", ",@retired))    if @retired;
  push(@logentry, "CHANGED: ".join(", ",@changed))    if @changed;
  push(@logentry, "NEW: "    .join(", ",@newentries)) if @newentries;
  my($numchanges) = @retired + @changed + @newentries;
  push(@logentry, "NO CHANGES") if $numchanges == 0;
  $numchanges;
}

sub do_the_update {
# construct a file name of a zip archive
  my($zipfile) = sprintf($zipfile_fmt, $sav_version_maj,$sav_version_min);
  my($lstfile) = sprintf($lstfile_fmt, $sav_version_maj,$sav_version_min);
# get modification time of the current local copy of the zip archive
  my($zip_mtime);
  if (-f "$savdir/$zipfile") {
    my(@stat) = stat("$savdir/$zipfile");
    if (!@stat) { die "Can't stat() file <$savdir/$zipfile>: $!" }
    else { $zip_mtime = $stat[9] }
  }
  my($ret);
# fetch zip archive with .ide files from the Sophos' web server
  eval { $ret = get_document("$urldir/$zipfile", "$tmpdir/$zipfile",
                             $zip_mtime, 1024*1024) };
  if ($@ ne '') {
    die $@;  # propagate error
  } elsif ($ret == RC_NOT_MODIFIED) {
    print "No need to refresh, <$savdir/$zipfile> is up to date ".
          "according to timestamps\n"  if $verbose >= 2;
    push(@logentry, "-");
  } elsif ($ret == RC_OK || $ret == RC_NOT_FOUND) {
    my($new_zip_exists) = ($ret == RC_OK);
    if ($new_zip_exists) {
      print "File <$tmpdir/$zipfile> downloaded successully\n"  if $verbose >= 2;
      push(@logentry, "DOWNLOADED (V$sav_version_maj.$sav_version_min)");
      unzip("$tmpdir/$zipfile", $tmpdir, $valid_ide_name_patt);
    } else {
      print "No zip archive at the Sophos site (no IDEs exist for version ".
            "$sav_version_maj.$sav_version_min)\n"  if $verbose >= 2;
      push(@logentry, "no zip (V$sav_version_maj.$sav_version_min)");
    }
    # NOTE: if $tmpdir is empty, existing .ide files will be removed
    my($numchanges) = merge_dir($savdir,$tmpdir);
    reload_sophie()  if $numchanges > 0;
    if (-f "$savdir/$zipfile") {
      if (-f "$savdir/$zipfile-superseded") {
        unlink("$savdir/$zipfile-superseded")
          or die "Can't remove file <$savdir/$zipfile-superseded>: $!";
      }
      rename("$savdir/$zipfile", "$savdir/$zipfile-superseded")
        or die "Can't rename <$savdir/$zipfile> to <$savdir/$zipfile-superseded>: $!";
    }
    # update this key file only after everything else has been done successfully
    if ($new_zip_exists) {
      link("$tmpdir/$zipfile", "$savdir/$zipfile")
        or die "Can't copy(link) <$tmpdir/$zipfile> to <$savdir/$zipfile>: $!";
    }
  } else {
    $! = 1; die "Unknown return code: $ret";
  }
}

# Remove directory along with all the files (matching pattern) it contains.
#
sub rmdir_with_files {
  my($dir,$patt) = @_;
  my($f);
  opendir(DIR, $dir) or die "Can't open directory <$dir>: $!";
  while (defined($f = readdir(DIR))) { 
    next if ($f =~ /^\.\.?$/) && -d("$dir/$f");
    if ($f !~ /$patt/) {
      $! = 1; die "File <$dir/$f> should not exist ".
                  "in this directory (pattern: /$patt/), not deleted";
    } elsif ($f =~ /^(.+)$/) {
      $f = $1;  # untaint after checking
      unlink("$dir/$f") or die "Can't remove file <$dir/$f>: $!";
    }
  }
  closedir(DIR) or die "Can't close directory <$dir>: $!";
  rmdir($dir) or die "Can't remove directory <$dir>: $!";
}

sub my_main {
  $savdir = get_sophos_data_directory();
  if (!defined($savdir)) {
    $! = 1;  die "Can't determine Sophos AV virus data directory";
  }
  ($sav_version_maj,$sav_version_min) = get_sophos_version();
  if (!defined($sav_version_maj)) {
    $! = 1;  die "Can't determine Sophos AV version number";
  }
# prepend "$savdir/" if $tmpdir and $log_filename are not absolute
  $tmpdir       = "$savdir/$tmpdir"        if $tmpdir       !~ m(^/);
  $log_filename = "$savdir/$log_filename"  if $log_filename !~ m(^/);

  umask(0022);   # go-w
  # $tmpdir is used as a temporary directory, as well as a locking mechanism
  # to guarantee than only one updating process is active at a time
  if (! mkdir($tmpdir, 0700) ) {  # can't get exclusive access
    # remember the true reason for a failure
    my($errmsg) = "Can't create new directory <$tmpdir>: $!";
    if (! -d($tmpdir) ) {
      die $errmsg;
    } else {  # directory exists, investigate further before deciding to die
      my(@stat) = stat($tmpdir);
      if (!@stat) {
        die "$errmsg, and can't stat() existing directory <$tmpdir>: $!";
      } else { # die if directory is older than two hours
        my($mtime) = $stat[9];
        my($age) = time - $mtime;
        if ($age > 2*3600) {  # two hours
          die "$errmsg; REMOVE OLD DIRECTORY MANUALLY!\n"
        } else {
          # otherwise silently go away under the assumption
          # that another process is already updating the thing
          # and it stalled for one reason or another
          print "$errmsg\n  ... but is not old enough (age = $age s), ".
                "exit for now, try again later\n"  if $verbose >= 1;
        }
      }
    }
  } else {  # we are alone, do the job
    umask(0133);   # u-x, go-wx
    eval { do_the_update() }; my($status) = $@;
    rmdir_with_files($tmpdir,  "($valid_ide_name_patt|^.*\.(zip|tmp)\$)" );
    if (! defined($log_filename)) {
      # no logging desired
    } elsif (! open(F,">>$log_filename")) {
      die "Can't append to file <$log_filename>: $!";
    } else {  # log update attempts
      # What is ISO 8601?  Check http://www.cl.cam.ac.uk/~mgk25/iso-time.html
      my($now_ISO8601) = strftime("%Y%m%dT%H%M%S", localtime);
      printf F ("%s %s\n",
                $now_ISO8601, (@logentry ? join("; ",@logentry) : $status) )
        or die "Can't write to file <$log_filename>: $!";
      close(F) or die "Can't close file <$log_filename>: $!";
    }
    if (!@logentry || (@logentry == 1 && $logentry[0] eq "-")) {
      # nothing worth reporting
    } else {
      send_mail($mail_from, $mail_to, $mail_subj, join("\n",@logentry));
    }
    if ($status) { die $status }  # propagate error
  }
}

sub printable {
  my($str) = @_;
  my(%map) = ("\r"=>'\r', "\n"=>'\n', "\f"=>'\f', "\b"=>'\b', "\e"=>'\e');
# expand tabs to 8-column spacing
# 1 while $str =~ s/\t+/' ' x (length($&)*8 - length($`)%8)/e;
# convert nonprintable to \x or \octal code
  $str =~ s/([\000-\037\177\200-\237\377])/
            exists($map{$1}) ? $map{$1} : sprintf("\\%03o",ord($1))/eg;
  $str =~ /^(.*)$/;
  $1;  # untaint after replacing funny characters with printable
}

# main program

  if (@ARGV > 0) {
    $mail_subj .= ' '  if $mail_subj ne '';
    $mail_subj .= '(' . printable(join(' ',@ARGV)) . ')';
  }
  for (@ARGV) {  # poor man's getopt - no need for a big cannon
    $neverfail++ if /^-s$/;
    $verbose++   if /^-v$/;
    $verbose+=2  if /^-vv/;
  }
  eval { my_main() }; my($status) = $@;
  if ($status ne '') {
    my($msg) = sprintf("FATAL ERROR (uid=%d,ppid=%d):\n  %s\n%s",
                       $>, getppid, $status, join("\n",@logentry));
    chomp($msg); chomp($msg);
    my($mail_sent) = 0;
    if (defined($mail_to)) {
      eval { $mail_sent = send_mail($mail_from, $mail_to,
                                    $mail_subj." -- FATAL ERROR", $msg) };
    }
    if ($mail_sent) {
      # problem was successfully reported by mail, so to avoid
      # double reporting it (e.g. by cron or mail pipe bounce)
      # we'll return success as an exit code!
      printf("%s; Mail sent to <%s>.\n", $status,$mail_to)  if $verbose >= 1;
    } elsif ($neverfail) {
      # always return success
      printf("%s\n", $status)  if $verbose >= 1;
    } else {
      # propagate error
      die $status;
    }
  }
  exit 0;
