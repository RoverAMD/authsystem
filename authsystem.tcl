package require sha1
package require base64

namespace eval authsys {
    proc _checkconnection {} {
        if {expr {! [info exists authsysTDBCConnection]} || expr {! [info exists authsysTDBCTable]}} {
            error "TDBC connection not initialized, please initialize it using \"authsys::use <TDBC connection initialization here> <table name>\""
        }
    }
    
    proc _quicksha {str} {
        set sha [sha1::sha1 [encoding convertto utf-8 $str]]
        return $sha
    }
    
    proc _quickbase64 {str} {
        return [string map {+ - / _ = {}} [base64::encode $str]]
    }
    
    proc _quickbase64d {str} {
        return [base64::decode [string map {- + _ /} $str]]
    }
    
    proc exists {username} {
        authsys::_checkconnection
        global authsysTDBCConnection
        global authsysTDBCTable
        $authsysTDBCConnection foreach record "SELECT * FROM $authsysTDBCTable" {
            if {[dict exists $record authsys_username] && [dict get $record authsys_username]} {
                return 1
            }
        }
        return 0
    }
    
    proc register {username password} {
        if {$additional_criteria == -1} {
            set additional_criteria [dict create]
        }
        authsys::_checkconnection
        if {[authsys::exists $username]} {
            error "The user with username $username already exists." 
        } elseif {[string first $username {"}] >= 0 || [string first $password {"}] >= 0} {
            error "Usernames or passwords cannot contain quoting symbols."
        }
        global authsysTDBCConnection
        global authsysTDBCTable
        set password [authsys::_quicksha $password]
        set qr "INSERT INTO $authsysTDBCTable (authsys_username, authsys_password) VALUES (\"$username\", \"$password\")"
        set st [$authsysTDBCConnection prepare $qr]
        set res [$st execute]
    }
    
    proc passwordcorrect {username password} {
        set hashtothis [authsys::_quicksha $password]
        authsys::_checkconnection
        if {! [authsys::exists $username]} {
            error "No user with username $username is registered on this service." 
        }
        global authsysTDBCConnection
        global authsysTDBCTable
        $authsysTDBCConnection foreach record "SELECT * FROM $authsysTDBCTable" {
            if {[dict exists $record authsys_username] && [dict exists $record authsys_password] && [dict get $record authsys_password] == $hashtothis && [dict get $record authsys_username] == $username} {
                return 1
            }
        }
        return 0
    }
    
    proc authtoken {username password {days 3}} {
        set ctime [clock seconds]
        set ntime [expr {$ctime + (24 * 60 * 60 * $days) + $days}]
        set tokenStr "$username/$password/$ctime/$ntime"
        return [authsys::_quickbase64 $tokenStr]
    }
    
    proc tokencorrect {tkn} {
        set tokenStr [authsys::_quickbase64d $tokenStr]
        set ctime [clock seconds]
        if {[string first $tokenStr /] < 0} {
            return 0
        }
        set token [split $tokenStr /]
        if {[llength $token] < 4 || ! [authsys::passwordcorrect [lindex $token 0] [lindex $token 1]]} {
            return 0
        }
        if {$ctime > [lindex $token 2] && $ctime < [lindex $token 3]} {
            return 1
        }
        return 0
    }
    
    proc use {conn tb} {
        if {[info exists authsysTDBCConnection] && [info exists authsysTDBCTable]} {
            error "Already initialized."
        }
        global authsysTDBCConnection
        global authsysTDBCTable
        set authsysTDBCTable $tb
        set authsysTDBCConnection $conn
    }
}