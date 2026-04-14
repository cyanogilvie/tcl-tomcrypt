if {"::tcltest" ni [namespace children]} {
	package require tcltest
	namespace import ::tcltest::*
}

::tcltest::loadTestedCommands

tcltest::testConstraint testMode [expr {[llength [info commands ::tomcrypt::_testmode_hasGetBytesFromObj]]>0}]

tcltest::testConstraint hasGetBytesFromObj	[expr {
	[llength [info commands ::tomcrypt::_testmode_hasGetBytesFromObj]] &&
	[tomcrypt::_testmode_hasGetBytesFromObj]
}]

tcltest::testConstraint have_crypto [expr {![catch {package require crypto}]}]
