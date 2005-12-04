<?xml version="1.0"?>
<!DOCTYPE slides-full PUBLIC "-//Norman Walsh//DTD Slides Full V3.3.1//EN"
 "http://docbook.sourceforge.net/release/slides/current/schema/dtd/slides-full.dtd" [

<!ENTITY ldif1 SYSTEM "addressbook-ldif/doe.xml">
<!ENTITY ldif2 SYSTEM "addressbook-ldif/smith.xml">
<!ENTITY session_01 SYSTEM "addressbook-session/session-01.xml">
<!ENTITY session_02 SYSTEM "addressbook-session/session-02.xml">
<!ENTITY session_03 SYSTEM "addressbook-session/session-03.xml">
<!ENTITY session_04 SYSTEM "addressbook-session/session-04.xml">
<!ENTITY session_05 SYSTEM "addressbook-session/session-05.xml">
<!ENTITY session_06 SYSTEM "addressbook-session/session-06.xml">
<!ENTITY session_07 SYSTEM "addressbook-session/session-07.xml">
<!ENTITY session_08 SYSTEM "addressbook-session/session-08.xml">
<!ENTITY session_09 SYSTEM "addressbook-session/session-09.xml">
<!ENTITY ldapentry_vs_oo SYSTEM "ldapentry-vs-oo.xml">
<!ENTITY search_inputs SYSTEM "search-inputs.xml">
]>

<slides>
  <slidesinfo>
    <title>Creating a simple LDAP application</title>
    <author>
      <firstname>Tommi</firstname>
      <surname>Virtanen &lt;tv@debian.org&gt;</surname>
    </author>

    <date>2004-06-09</date>
    <copyright>
      <year>2003&ndash;2004</year>
      <holder>Tommi Virtanen</holder>
    </copyright>
  </slidesinfo>

  <foil>
    <title>LDAP presents a distributed tree of information</title>
    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="ldap-is-a-tree.dia.png"/>
      </imageobject>
    </mediaobject>
  </foil>

  <foil>
    <title>Writing things down: LDIF</title>
    <literallayout>&ldif1;</literallayout>
  </foil>

  <foil>
    <title>Writing things down: LDIF</title>
    <literallayout>&ldif2;</literallayout>
  </foil>

  <foil>
    <title>Setting up an LDAP server in 5 seconds</title>
    <para>...</para>
  </foil>

  <foil>
    <title>Python, an easy programming language</title>
    <para>
      <phrase>Batteries included!</phrase>
    </para>

    <para>Python combines remarkable power with very clear syntax.</para>

    <para>Runs on many brands of UNIX, on Windows, OS/2, Mac, Amiga,
    and many other platforms.</para>
  </foil>

  <foil>
    <title>The first step</title>
    <literallayout>&session_01;</literallayout>
  </foil>

  <foil>
    <title>Ldaptor</title>
    <para>Ldaptor is a set of pure-Python LDAP client programs,
      applications and a programming library.</para>
    <para>It is licensed under the GNU LGPL.</para>
  </foil>

  <foil>
    <title>Overview of Ldaptor</title>
    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="overview.dia.png"/>
      </imageobject>
    </mediaobject>
  </foil>

  <foil>
    <title>Preparing to connect</title>
    <literallayout>&session_02;</literallayout>
  </foil>

  <foil>
    <title>Twisted</title>

    <para>Twisted is an event-driven networking framework written in
    Python and licensed under the LGPL.</para>

    <para>Twisted supports TCP, UDP, SSL/TLS, multicast, Unix sockets,
    a large number of protocols (including HTTP, NNTP, SSH, IRC, FTP,
    and others), and much more.</para>

    <para>Twisted includes many fullblown applications, such as web,
    SSH, FTP, DNS and news servers.</para>
  </foil>

  <foil>
    <title>Connecting</title>
    <literallayout>&session_03;</literallayout>
  </foil>

  <foil>
    <title>Deferreds</title>

    <itemizedlist>
      <listitem>
	<para>A promise that a function will at some point have a
	result.</para>
      </listitem>
      <listitem>
	<para>You can attach callback functions to a Deferred.
	  Once it gets a result these callbacks will be called.</para>
      </listitem>
      <listitem>
	<para>Also allows you to register a callback for an error,
	  with the default behavior of logging the error.</para>
      </listitem>
      <listitem>
	<para>Standard way to handle all sorts of blocking or delayed
	operations.</para>
      </listitem>
    </itemizedlist>
  </foil>

  <foil>
    <title>Searching</title>
    <literallayout>&session_04;</literallayout>
  </foil>

  <foil>
    <title>Results</title>
    <literallayout>&session_05;</literallayout>
  </foil>

  <foil>
    <title>Results one-by-one</title>
    <literallayout>&session_06;</literallayout>
  </foil>

  <foil>
    <title>LDIF output</title>
    <literallayout>&session_07;</literallayout>
  </foil>

  <foil>
    <title>Closing the connection</title>
    <literallayout>&session_08;</literallayout>
  </foil>

  <foil>
    <title>Access to entry details</title>
    <literallayout>&session_09;</literallayout>
  </foil>

  <foil>
    <title>Object-oriented look at LDAP entries</title>

    <para>A lot of similarities with OO programming languages, but
    some big differences, too.</para>

    &ldapentry_vs_oo;
  </foil>

  <foil>
    <title>Search inputs</title>
    &search_inputs;

    <para>An example search filter:</para>
    <literallayout>(cn=John Smith)</literallayout>
  </foil>

  <foil>
    <title>Our first Python program</title>
    <para>
      <ulink url="02_script/addressbook-py.html">Click me!</ulink>
    </para>
  </foil>

  <foil>
    <title>Phases of the protocol chat</title>
    <orderedlist>
      <listitem>
	<para>Open and bind</para>
      </listitem>
      <listitem>
	<para>Search (possibly many times)</para>
      </listitem>
      <listitem>
	<para>Unbind and close</para>
      </listitem>
    </orderedlist>
  </foil>

  <foil>
    <title>Opening and binding</title>
    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="chat-bind.dia.png"/>
      </imageobject>
    </mediaobject>
  </foil>

  <foil>
    <title>Doing a search</title>
    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="chat-search.dia.png"/>
      </imageobject>
    </mediaobject>
  </foil>

  <foil>
    <title>Doing multiple searches</title>
    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="chat-search-pipeline.dia.png"/>
      </imageobject>
    </mediaobject>
  </foil>

  <foil>
    <title>Unbinding and closing</title>
    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="chat-unbind.dia.png"/>
      </imageobject>
    </mediaobject>
  </foil>

  <foil>
    <title><ulink url="http://www.divmod.org/Home/Projects/Nevow/">Nevow</ulink></title>
    <itemizedlist>
      <listitem>
	<para>A web application framework for building highly
	interactive web applications.</para>
      </listitem>
      <listitem>
	<para>Separates HTML templates from page-generation
	logic.</para>
      </listitem>
      <listitem>
	<para>Uses the Model-View-Controller (MVC) pattern to create
	dynamic HTML on the fly.</para>
      </listitem>
    </itemizedlist>
  </foil>

  <foil>
    <title>A Web App: Code</title>
    <para>
      <ulink url="07_easy/addressbook-py.html">Click me!</ulink>
    </para>
  </foil>

  <foil>
    <title>A Web App: Template</title>
    <para>
      <ulink url="07_easy/searchform-xhtml.html">Click me!</ulink>
    </para>
  </foil>

  <foil>
    <title>A Web App: Startup</title>
    <para>
      <ulink url="07_easy/addressbook-tac.html">Click me!</ulink>
    </para>
  </foil>

  <foil>
    <title>A complex search filter</title>

    <literallayout>
      (&amp;(objectClass=person)
          (!(telephoneNumber=*))
          (|(cn=*a*b*)(cn=*b*a*)))
    </literallayout>

    <mediaobject>
      <imageobject>
	<imagedata format="PNG" align="center" fileref="ldapfilter-as-tree.dia.png"/>
      </imageobject>
    </mediaobject>

  </foil>

  <foil>
    <title>Objectclasses</title>

    <itemizedlist>
      <listitem>
	<para>Special attribute <literal>objectClass</literal> lists
	all the objectclasses an LDAP entry manifests.</para>
      </listitem>
      <listitem>
	<para>Objectclass defines</para>
	<itemizedlist>
	  <listitem>
	    <para>what attributetypes an entry MUST have</para>
	  </listitem>
	  <listitem>
	    <para>what attributetypes an entry MAY have</para>
	  </listitem>
	</itemizedlist>
      </listitem>
      <listitem>
	<para>An entry in a phonebook must have a name and a telephone
	number, and may have a fax number and street address.</para>
      </listitem>
    </itemizedlist>
  </foil>

  <foil>
    <title>Schema</title>
    <itemizedlist>
      <listitem>
	<para>a configuration file included in the LDAP server
	configuration.</para>
      </listitem>
      <listitem>
	<para>a combination of attribute type and object class
	definitions.</para>
      </listitem>
      <listitem>
	<para>stored as plain text</para>
      </listitem>
      <listitem>
	<para>can be requested over an LDAP connection</para>
      </listitem>
    </itemizedlist>
  </foil>

  <foil>
    <title>Attribute type</title>
    <programlisting>
attributetype ( 2.5.4.4 NAME ( 'sn' 'surname' )
	DESC 'RFC2256: last (family) name(s) for
              which the entity is known by'
	SUP name )
    </programlisting>

    <para>Can also contain</para>
    <itemizedlist>
      <listitem>
	<para>content data type</para>
      </listitem>
      <listitem>
	<para>comparison and sort mechanism</para>
      </listitem>
      <listitem>
	<para>substring search mechanism</para>
      </listitem>
      <listitem>
	<para>whether multiple values are allowed</para>
      </listitem>
    </itemizedlist>
  </foil>

  <foil>
    <title>Object class</title>
    <programlisting>
objectclass ( 2.5.6.6 NAME 'person'
	DESC 'RFC2256: a person'
	SUP top STRUCTURAL
	MUST ( sn $ cn )
	MAY ( userPassword $ telephoneNumber
		$ seeAlso $ description ) )
    </programlisting>
  </foil>

  <foil>
    <title>Creating schemas</title>
    <itemizedlist>
      <listitem>
	<para>Anyone can create their own schema</para>
      </listitem>
      <listitem>
	<para>Need to be globally unique</para>
      </listitem>
      <listitem>
	<para>But try to use already existing ones</para>
      </listitem>
    </itemizedlist>
  </foil>

  <foil>
    <title>Demo of ldaptor-webui</title>
    <para>...</para>
  </foil>

  <foil>
    <title>Where to go from here?</title>

    <para>Install <ulink
    url="http://www.openldap.org/">OpenLDAP</ulink>.</para>

    <para>Install <ulink
    url="http://tv.debian.net/software/ldaptor/">Ldaptor</ulink>, play
    around with ldaptor-webui.</para>

    <para>Learn <ulink url="http://www.python.org/">Python</ulink>.</para>

    <para>Learn Twisted. Write a client application for a simple
    protocol. Read <ulink
    url="http://twistedmatrix.com/documents/howto/clients">the
    HOWTOs</ulink>.</para>

  </foil>

  <foil>
    <title>Thank You</title>
    <para>Questions?</para>
  </foil>

<!--

Local Variables:
coding: utf-8
End:

-->

</slides>
