package require tdbc::sqlite3
source authsystem.tcl

tdbc::sqlite3::connection create db demo.sqlite3
authsys::use db users

puts "Login or register?"
puts "1 - Login"
puts "2 - Register"
gets stdin choice
if {$choice != 1 && $choice != 2} {
	puts "Aborted."
	exit 1
} 

puts "Username:"
gets stdin un
puts "Password:"
gets stdin password
if {$choice == 1} {
	if {[authsys::exists $un]} {
		puts "User \"$un\" already registered."
		exit 2
	}
	authsys::register $un $password
	puts "Created user \"$username\" with password \"$password\".'
} elseif {$choice == 2} {
	set token [authsys::authtoken $un $password] ;# if the username, password is incorrect or the token itself has expired, then tokencorrect returns 0
	if {! [authsys::tokencorrect $token]} {
		puts "Token $token is incorrect."
	} else {
		puts "Token $token is correct."
	}
}
