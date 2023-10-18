#! /usr/bin/env perl
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause
#
# This file is dual-licensed, meaning that you can use it under your
# choice of either of the following two licenses:
#
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You can obtain
# a copy in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# or
#
# Copyright (c) 2023, Christoph Müllner <christoph.muellner@vrull.eu>
# Copyright (c) 2023, Jerry Shih <jerry.shih@sifive.com>
# Copyright (c) 2023, Phoebe Chen <phoebe.chen@sifive.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

# Set $have_stacktrace to 1 if we have Devel::StackTrace
my $have_stacktrace = 0;
if (eval {require Devel::StackTrace;1;}) {
    $have_stacktrace = 1;
}

my @regs = map("x$_",(0..31));
# Mapping from the RISC-V psABI ABI mnemonic names to the register number.
my @regaliases = ('zero','ra','sp','gp','tp','t0','t1','t2','s0','s1',
    map("a$_",(0..7)),
    map("s$_",(2..11)),
    map("t$_",(3..6))
);

my %reglookup;
@reglookup{@regs} = @regs;
@reglookup{@regaliases} = @regs;

# Takes a register name, possibly an alias, and converts it to a register index
# from 0 to 31
sub read_reg {
    my $reg = lc shift;
    if (!exists($reglookup{$reg})) {
        my $trace = "";
        if ($have_stacktrace) {
            $trace = Devel::StackTrace->new->as_string;
        }
        die("Unknown register ".$reg."\n".$trace);
    }
    my $regstr = $reglookup{$reg};
    if (!($regstr =~ /^x([0-9]+)$/)) {
        my $trace = "";
        if ($have_stacktrace) {
            $trace = Devel::StackTrace->new->as_string;
        }
        die("Could not process register ".$reg."\n".$trace);
    }
    return $1;
}

my @vregs = map("v$_",(0..31));
my %vreglookup;
@vreglookup{@vregs} = @vregs;

sub read_vreg {
    my $vreg = lc shift;
    if (!exists($vreglookup{$vreg})) {
        my $trace = "";
        if ($have_stacktrace) {
            $trace = Devel::StackTrace->new->as_string;
        }
        die("Unknown vector register ".$vreg."\n".$trace);
    }
    if (!($vreg =~ /^v([0-9]+)$/)) {
        my $trace = "";
        if ($have_stacktrace) {
            $trace = Devel::StackTrace->new->as_string;
        }
        die("Could not process vector register ".$vreg."\n".$trace);
    }
    return $1;
}

# Read the vm settings and convert to mask encoding.
sub read_mask_vreg {
    my $vreg = shift;
    # The default value is unmasked.
    my $mask_bit = 1;

    if (defined($vreg)) {
        my $reg_id = read_vreg $vreg;
        if ($reg_id == 0) {
            $mask_bit = 0;
        } else {
            my $trace = "";
            if ($have_stacktrace) {
                $trace = Devel::StackTrace->new->as_string;
            }
            die("The ".$vreg." is not the mask register v0.\n".$trace);
        }
    }
    return $mask_bit;
}

# Vector crypto instructions

## Zvbb and Zvkb instructions
##
## vandn (also in zvkb)
## vbrev
## vbrev8 (also in zvkb)
## vrev8 (also in zvkb)
## vclz
## vctz
## vcpop
## vrol (also in zvkb)
## vror (also in zvkb)
## vwsll

sub vbrev8_v {
    # vbrev8.v vd, vs2, vm
    my $template = 0b010010_0_00000_01000_010_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vm = read_mask_vreg shift;
    return ".word ".($template | ($vm << 25) | ($vs2 << 20) | ($vd << 7));
}

sub vrev8_v {
    # vrev8.v vd, vs2, vm
    my $template = 0b010010_0_00000_01001_010_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vm = read_mask_vreg shift;
    return ".word ".($template | ($vm << 25) | ($vs2 << 20) | ($vd << 7));
}

sub vror_vi {
    # vror.vi vd, vs2, uimm
    my $template = 0b01010_0_1_00000_00000_011_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $uimm = shift;
    my $uimm_i5 = $uimm >> 5;
    my $uimm_i4_0 = $uimm & 0b11111;

    return ".word ".($template | ($uimm_i5 << 26) | ($vs2 << 20) | ($uimm_i4_0 << 15) | ($vd << 7));
}

sub vwsll_vv {
    # vwsll.vv vd, vs2, vs1, vm
    my $template = 0b110101_0_00000_00000_000_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vs1 = read_vreg shift;
    my $vm = read_mask_vreg shift;
    return ".word ".($template | ($vm << 25) | ($vs2 << 20) | ($vs1 << 15) | ($vd << 7));
}

## Zvbc instructions

sub vclmulh_vx {
    # vclmulh.vx vd, vs2, rs1
    my $template = 0b0011011_00000_00000_110_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $rs1 = read_reg shift;
    return ".word ".($template | ($vs2 << 20) | ($rs1 << 15) | ($vd << 7));
}

sub vclmul_vx_v0t {
    # vclmul.vx vd, vs2, rs1, v0.t
    my $template = 0b0011000_00000_00000_110_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $rs1 = read_reg shift;
    return ".word ".($template | ($vs2 << 20) | ($rs1 << 15) | ($vd << 7));
}

sub vclmul_vx {
    # vclmul.vx vd, vs2, rs1
    my $template = 0b0011001_00000_00000_110_00000_1010111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $rs1 = read_reg shift;
    return ".word ".($template | ($vs2 << 20) | ($rs1 << 15) | ($vd << 7));
}

## Zvkg instructions

sub vghsh_vv {
    # vghsh.vv vd, vs2, vs1
    my $template = 0b1011001_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vs1 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20) | ($vs1 << 15) | ($vd << 7));
}

sub vgmul_vv {
    # vgmul.vv vd, vs2
    my $template = 0b1010001_00000_10001_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

## Zvkned instructions

sub vaesdf_vs {
    # vaesdf.vs vd, vs2
    my $template = 0b101001_1_00000_00001_010_00000_1110111;
    my $vd = read_vreg  shift;
    my $vs2 = read_vreg  shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

sub vaesdm_vs {
    # vaesdm.vs vd, vs2
    my $template = 0b101001_1_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

sub vaesef_vs {
    # vaesef.vs vd, vs2
    my $template = 0b101001_1_00000_00011_010_00000_1110111;
    my $vd = read_vreg  shift;
    my $vs2 = read_vreg  shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

sub vaesem_vs {
    # vaesem.vs vd, vs2
    my $template = 0b101001_1_00000_00010_010_00000_1110111;
    my $vd = read_vreg  shift;
    my $vs2 = read_vreg  shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

sub vaeskf1_vi {
    # vaeskf1.vi vd, vs2, uimmm
    my $template = 0b100010_1_00000_00000_010_00000_1110111;
    my $vd = read_vreg  shift;
    my $vs2 = read_vreg  shift;
    my $uimm = shift;
    return ".word ".($template | ($uimm << 15) | ($vs2 << 20) | ($vd << 7));
}

sub vaeskf2_vi {
    # vaeskf2.vi vd, vs2, uimm
    my $template = 0b101010_1_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $uimm = shift;
    return ".word ".($template | ($vs2 << 20) | ($uimm << 15) | ($vd << 7));
}

sub vaesz_vs {
    # vaesz.vs vd, vs2
    my $template = 0b101001_1_00000_00111_010_00000_1110111;
    my $vd = read_vreg  shift;
    my $vs2 = read_vreg  shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

## Zvknha and Zvknhb instructions

sub vsha2ms_vv {
    # vsha2ms.vv vd, vs2, vs1
    my $template = 0b1011011_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vs1 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20)| ($vs1 << 15 )| ($vd << 7));
}

sub vsha2ch_vv {
    # vsha2ch.vv vd, vs2, vs1
    my $template = 0b101110_10000_00000_001_00000_01110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vs1 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20)| ($vs1 << 15 )| ($vd << 7));
}

sub vsha2cl_vv {
    # vsha2cl.vv vd, vs2, vs1
    my $template = 0b101111_10000_00000_001_00000_01110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vs1 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20)| ($vs1 << 15 )| ($vd << 7));
}

## Zvksed instructions

sub vsm4k_vi {
    # vsm4k.vi vd, vs2, uimm
    my $template = 0b1000011_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $uimm = shift;
    return ".word ".($template | ($vs2 << 20) | ($uimm << 15) | ($vd << 7));
}

sub vsm4r_vs {
    # vsm4r.vs vd, vs2
    my $template = 0b1010011_00000_10000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20) | ($vd << 7));
}

## zvksh instructions

sub vsm3c_vi {
    # vsm3c.vi vd, vs2, uimm
    my $template = 0b1010111_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $uimm = shift;
    return ".word ".($template | ($vs2 << 20) | ($uimm << 15 ) | ($vd << 7));
}

sub vsm3me_vv {
    # vsm3me.vv vd, vs2, vs1
    my $template = 0b1000001_00000_00000_010_00000_1110111;
    my $vd = read_vreg shift;
    my $vs2 = read_vreg shift;
    my $vs1 = read_vreg shift;
    return ".word ".($template | ($vs2 << 20) | ($vs1 << 15 ) | ($vd << 7));
}

1;
