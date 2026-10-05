"""Active Directory exploitation gap module — thin wrappers around
BloodHound-python, Impacket, NetExec/CrackMapExec, and Certipy.

These tools are external CLIs the user installs themselves; we shell out
via :mod:`pencheff.core.tool_runner` and parse their output into
``Finding`` / engagement-DB rows.
"""
