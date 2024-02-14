#!/usr/bin/perl

# Copy this program to dir with messages to test
# Attention! It will change contents of the messages
# by adding SpamAssassin headers

use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::NoMailAudit;


my $spamtest = Mail::SpamAssassin->new({
         dont_copy_prefs => 1,
         local_tests_only => 0,
         stop_at_threshold => 0,
         debug => 0,
         paranoid => 0,
});


opendir(DIR, ".") or die "cannot open current directory.";
    while (defined (my $filename = readdir(DIR))) {
        if (($filename ne "testmessages.pl") &&
            (-f $filename) && (-r $filename)) {
            print "$filename\n";
            &check_file($filename);
        }
    }

closedir(DIR);


sub check_file {
    my $filename = shift;
    my $cgp_header = 1;
    my @msglines;


    # Now read in message file
    open(MSGFILE, "$filename") or die "Cannot read file: $filename";
    foreach my $line (<MSGFILE>) {
        # skip the CommuniGate headers
        if ($cgp_header) {
    	    if ($line =~ /^\s+$/) {
                $cgp_header = 0;
            }    
            next;
        }   
        push(@msglines, $line); 
    }
    close(MSGFILE);

    my $mail = Mail::SpamAssassin::NoMailAudit->new(
                        	    data => \@msglines,
                            	    add_From_line => 0
                        	    );


    # Now use copy-on-writed (hopefully) SA object
    my $status = $spamtest->check($mail);
    $status->rewrite_mail();

    # add the spam report to the end of the body as well, if testing.
    my $lines = $mail->body();
    push (@{$lines}, split(/$/, $status->get_report()));
    $mail->body($lines);

    open(MSGFILE, ">$filename") or die "Cannot write to file: $filename";
        print MSGFILE $mail->header(), "\n", join ('', @{$mail->body()});
    close(MSGFILE);
    
}