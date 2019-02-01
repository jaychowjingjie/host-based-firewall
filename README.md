# Jay Chow, 24th January 2019 

### Running the Python3 firewall program:
python3 firewall.py 

Note: please edit the file path in line 158 of firewall.py to where the csv file is.

### Background:
As a simplified model, consider a firewall to be a system which is programmed with
a set of predetermined security rules. As network traffic enters and leaves
the machine, the firewall rules determine whether the traffic should be
allowed or blocked.Real‐world firewalls support both “allow” and “block”
rules, and their ordering is important in determining the fate of a packet.
In this coding exercise, we only support the “allow” rules. If a packet does
not match any “allow” rule, then we assume it will be blocked.

A firewall is a part of computer system or network designed to stop
unauthorized traffic flowing from one network to another. It is used to
separate trusted and untrusted components of a network and to differentiate
networks within a trusted network. The main functionalities are filtering
data, redirecting traffic and protecting against network attacks.

### Goal:
1) The ability to write functional code, define/refine scope and requirements.
2) The demonstration of a solid grasp of concepts in software engineering, such as clean interfaces, code reuse, modularity.
3) A consideration of system and algorithmic performance, as well as a consideration of reasonable edge cases – a reasonable test plan and execution.


### Design, Implementation and Complexity Analysis:

I used the full 90 minutes in total for this assignment. Since I had to start from scratch, 
I chose the object-oriented, interpreted python programming language for this challenege as 
it is faster and more time-efficient to code with the pre-built csv, ipaddress and unittest modules. 


In terms of the choice of the data structure, I decided to use python lists as they are flexible and 
can hold heterogeneous, arbitrary data. In addition, they can be appended to very efficiently, 
in amortized constant time. However, python lists use a lot more space than C arrays but use less space that python
dictionaries. In other words, I decided to go with python lists for this coding assignment instead of C arrays in C or C++. 
Recall that linked lists and C arrays in C or C++ are worst-case O(N) for either searching or inserting elements. Since I have 
more experience in C and C++ but did not use C or C++ for this coding assignment, I did not consider the data structures 
associated with C or C++ (vectors, hash tables, C arrays, linked lists etc)

However, if I had more time, I would use a lower level, compiled language
such as C or C++ for speed and reduced latency. However, using a lower level
language such as C will lead to more bugs as there are less preventive
measures when dealing with pointers and dynamic memory to control the
lifetime of certain variables and data structures on
the heap. If I had a few days to implement this again, I would have used C++
or C in a OOP manner with inheritance, having a base Firewall Class with
basic functionalities and then building more advanced types of firewalls
from this base class. To be more specific, I could have a packet filter
firewall that controls traffic based on the information in packet headers, a
stateful firewall that tracks the state of traffic by monitoring all the
connection interactions until is closed or an application/firewall
that controls input, output and access from/to an application or service. I would 
have also added more error and security checking code such as to ensure input is well formatted and more
defensive programming to prevent buffer overflows when dealing with input files that could be controlled 
by a malicious user.


Analysis of the constructor, taking a single string argument, which is a file path to a CSV file:

I used a list of lists to store the rules when I initialized a firewall in my code, keeping it simple due to the time 
constraint. Although a list of lists is easy to code and iterate, the construction of the Firewall is O(4*n) = O(4n), where 4
is the size of each sub-list, and n is the size of the outer list, which is the number of rows in the CSV file. Therefore,
self.rules is built from the CSV file, taking O(4n) time. However, it is important to keep in mind that this is not 
considering the time to access the CSV file on the file system during construction.

Analysis of accept_packet(self, direction, protocol, port, ip_address):
Recall that my list of lists has size of n * 4, where n is the number of rows in the CSV file. So in my algorithm,
I iterated over all n elements in the outer list, and since I know that rules[0] is the direction, rules[1] is the protocol,
rules[2] is the port and rules[3] is the ip_address, comparing the value from the test to the value in the rule will take
O(n*1) = O(n) time, since I already know the index that corresponds to a specific attribute such as direction, protocol, port
or ip_address. In the outer loop, I iterated over each sub-list in the outer list. In the inner loop, since I only had 4 
elements in each sub-list, I made sure that a network packet will be accepted by the firewall if and only if the direction,
protocol, port, and IP address match at least one of the input rules. If 1 security rule is matched exactly, this function 
immediately returns true. In other words, the worst case is O(4n), which is linear in the terms of the number of rows in the
CSV file.



### Testing

For testing, I used the unittest module for unit testing on my host-based firewall. I created a Firewall_Test class to unit 
test in order convince myself of the correctness and performance of my code. There are the member functions within the 
Firewall_Test class. Additionally, I added additional edge test cases across my test functions within Firewall_Test class to 
ensure that my firewall is correctly implemented considering the edge cases. 

For this assignment, I have assumed that the input from the CSV file is properly well-formatted. However, in industry, I 
should not rely on this assumption. Therefore, to improve on this assignment, I could do input validation to ensure that my 
program does not crash clumsily when given bad input. Instead, I could further raise exceptions to return control back to the 
user if the input is not well-formatted. Python does provide a rich library of exception handling functionalities that I could 
import to use in my code.

Throughout this assignment, I performed incremental execution and debugging using print statements to keep track of my 
variables and data structures to ensure that my Firewall was working correctly. If I had a more complex assignment with more 
time, I would have used the pdb debugger on top of regular print statements to make debugging easier.


### Future Optimizations/Improvements:

1) Since there may be a massive number of rules (use 500K entries as a baseline), and real-­world firewalls must be able to
store this in a reasonably compact form while introducing only negligible latency to incoming and outgoing network traffic, 
this linear-time algorithm may not be the most efficient in terms of speed. As such, using a python dictionary with O(1) 
lookup may seem to be a better option initially. However, for the outer data structure, I will still argue that using a list 
instead of a dictionary is better for this specific program because I need to check if at least one security rule is matched. 
In other words, when a packet comes in, the best case is that the first rule stored internally within the Firewall matches the 
rule that is associated with incoming packet. The worst case is none matches and the whole list has to be iterated. For the 
inner data structure, there is no use for a dictionary as I already know that the 0th column corresponds to the direction, the 
1st column corresponds to the protocol etc. Indexing by number is sufficient. To further support my choice of python lists, a 
python dictionars have higher RAM overhead compared to a list. If we have a very large number of rules from the csv, not all 
the security rules could fit into RAM if we use dictionaries as the underlying data structures. And what would the key be in 
this case for the outer data structure? As such, I could only see the value in using a dictionary of lists if I need to look 
up a specific security rule very quickly. In that case, we could use keys such as time stamp, source or destination IP as the 
keys. If duplicate values must be allowed for a specific key, I could then use a dictionary or a list as the value field. This 
depends on the purpose and the context of what is needed from the firewall.

2) If I had the opportunity to carry on working on this software project, I would make my firewall more immune to penetration, 
which implies using a hardened system with secured Operating Systems to minimize the exploit of security vulnerabilities. 
Instead of just getting the input rules from a CSV file, firewalls should only authorized traffic defined by security 
policies. In other words, this host-based firewall for the coding assignment is over-simplified and not realistic. Examples of 
firewall policies include:

- User control: Controls access to the data based on the role of the user who is attempting to access the host machine.
- Service control: Controls access by the type of service offered by the host. Applied on the basis of network address, 
protocol of connection and port numbers.
- Direction control: Determines the direction in which requests may be initiated and are allowed to flow through the firewall. 
It tells whether the traffic is “inbound” or vice-versa “outbound”
 
3) If I had even more time to make the firewall more intellgent, I would have used a high-performance container datatype such 
as an OrderedDict that remembers the order entries were added. Ordered dictionaries are regular dictionaries but they remember 
the order that items were inserted. When iterating over an ordered dictionary, the items are returned in the order their keys 
were first added. This could be useful if we decided to make our host-based firewall more intelligent by remember the order. 
For example, it could be used to track the order of packets entering or leaving the machine, order of applications that are 
utilizing the firewall or the order of the "allow" rules that are configured for a specific firewall on a host machine. This 
will allow easier management of a firewall for an administrator since many rules are stacked on top of one another. Since it 
is still a regular dictionary under the hood, the look up complexity is still O(1). As such, speed is not really sacrificed 
for added functionality that could be useful if we decide to make our host-based firewall more intelligent for future 
improvement in this host-based firewall.

### Miscellaneous
During my graduate coursework at Johns Hopkins University Information Security Institute, I built a Firewall using Netfilter,
a packet filter firewall implementation in Linux. Note that packet filtering can be done inside the kernel as changes are
needed in the kernel. Linux provides two mechanisms to achieve this :
- Netfilter: Provides hooks at critical points on the packet traversal path inside Linux Kernel.
- Loadable Kernel Modules: Allow privileged users to dynamically add/remove
modules to the kernel, so there is no need to recompile the entire kernel.
