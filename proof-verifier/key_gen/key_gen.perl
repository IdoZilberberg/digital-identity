#!/usr/bin/perl
my $file = $ARGV[0];

open my $info, $file or die "Could not open $file: $!";
$count = 0;
$prefix = ', _ := curve.MakeG2Point(parseBigIntArray("';
$prefixArr = ', _ = curve.MakeG2Point(parseBigIntArray("';
$suffix = '"), true)';
print "func verifyingKey(curve curves.CurveSystem) (vk verifyingKeyStruct) {
";
while( my $line = <$info>)  {
    chomp($line);
    $line =~ m/vk\.(.*?) /;
    $name = $1;
    $line =~ m/= (.*)/;
    $data = $1;
    if ($line =~ m/gammaABC\.len/) {
        $name =~ m/(.*)\.len/;
        $name = $1;
        print "var ".$name." [".$data."]curves.Point\n";
    } else {
        $data =~ s/\[//g;
        $data =~ s/\]//g;
        $data =~ s/ //g;
        if ($name =~ m/gammaABC/) {
            print $name.$prefixArr.$data.$suffix."\n";
        } else {
            print $name.$prefix.$data.$suffix."\n";
        }
    }
}
print "vk = verifyingKeyStruct{a: alpha, b: beta, gamma : gamma, delta : delta, gammaABC : gammaABC[:]}\n";
print "return\n";
print "}\n";
