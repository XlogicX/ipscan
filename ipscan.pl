#!/usr/bin/perl

use warnings;
use strict;

#Calculate checksum given IP header info
sub checksum($){
	my $sum = shift;										#Get our header info passed to this sub
	my $length;												#Create container for IP length
	if ($sum =~ /^.(.)/) { 									#Parse out the 2nd nibble (IP length)
		$length = hex($1);									#Hex->Decimal conversion of it
		$length *= 4;										#Multiply by 4 (it's an IP thing)
		$length = ($length * 2) - 24;						#length no longer length, but offset for how much data AFTER checksum
	}
	$sum =~ s/^(\w{20})....(.{$length}).*/$1$2/;			#Get rid of checksum bytes

	#Get 2byte words for all header data (to sum)
	my $i = 0;						#init the loop cntr
	my @words;						#array for 2-byte words for adding
	while ($sum) {					#while there is still data in our remaining header data
		if ($sum =~ /^(.{4})/) {	#parse out the first 4 characters (nibbles) (2-bytes)
			$words[$i] = $1;		#add it to our array
		$sum =~ s/^.{4}//;			#remove it from $sum
		}
		$i++;						#inc the cntr for next 2-bytes (until done)
	}

	#Add all the 2-byte values up
	my $wordcount = @words;			#how many values are we adding? (unknown due to IP options)
	$i = 0;							#init the loop cntr
	$sum = 0;						#init our total
	while ($i < $wordcount) {		#keep adding until we've added all of the words
		$sum += hex($words[$i]);	#add a decimal form of our ASCII-Hex 2-bytes
		$i++;						#inc the cntr for next 2-bytes to add
	}

	#Determine what value overflowed into carry (past 2 bytes)
	my $hexsum = sprintf("%.4X\n", $sum);	#Just get the Least Significant nibbles
	my $carry;								#create container for value of carry
	if ($hexsum =~ /(.+).{4}$/) {			#if there are 5+ nibbles, parse the Most Significant nibble
		$carry = $1;						#store it as the carry
	} else {								#otherwise
		$carry = 0;								#it's zero
	}

	#Now add the carry to the non-overflowed sum
	$sum += hex($carry);						#add the carry to the non-overflowed sum		
	$sum = sprintf("%.4X\n", $sum);		#Re-ASCII-hex it
	if ($sum =~ /.+(.{4})$/) {			#Regex to lop off the carry part
		$sum = $1;
	}

	$sum =~ tr/0123456789ABCDEF/FEDCBA9876543210/;	#mathemetically equiv to FFFF-$sum or 1's compliment

	return $sum;							#Return the resulting checksum
}

my $packet;
my $reported_sum;
my $inputfile = shift @ARGV;
my $yes = 0;
my $no = 0;

open FILE, $inputfile or die "Couldn't open file $!\n";

$/ = undef;
my $data = <FILE>;
$/ = "\n";

my $bytes = '';
for (unpack "(H2)*", $data) {
	$bytes .= "$_ ";
}

while ($bytes =~ /.+?4([^\s])/) {
	my $offset = (hex($1) * 4) - 1;
	my $removal = $&;
	if (($offset == 19) && ($bytes =~ /.+?(4[^\s])((\s..){\Q$offset\E})/)) {
		$packet = "$1$2";
		$packet =~ s/\s//g;
		my $result = checksum($packet);	
		if ($packet =~ /.{20}(....)/) {
			$reported_sum = $1;
		}
		if ($result =~ /\Q$reported_sum\E/i) {
			$yes++;
		} else {
			$no++;
		}
	}
	$bytes =~ s/$removal//;
}

print "IP No Options (Higher Fidelity): $yes / " . ($yes + $no) . "\n";

$yes = $no = 0;
$bytes = '';
for (unpack "(H2)*", $data) {
	$bytes .= "$_ ";
}

while ($bytes =~ /.+?4([^\s])/) {
	my $offset = (hex($1) * 4) - 1;
	my $removal = $&;
	if (($offset >= 19) && ($bytes =~ /.+?(4[^\s])((\s..){\Q$offset\E})/)) {
		$packet = "$1$2";
		$packet =~ s/\s//g;
		my $result = checksum($packet);	
		if ($packet =~ /.{20}(....)/) {
			$reported_sum = $1;
		}
		if ($result =~ /\Q$reported_sum\E/i) {
			$yes++;
		} else {
			$no++;
		}
	}
	$bytes =~ s/$removal//;
}

print "With Options (Lower Fidelity): $yes / " . ($yes + $no) . "\n";
