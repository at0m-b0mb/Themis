"""Themis -- exam integrity built on controls that hold.

Design invariant, enforced by review not by convention: no module in this package
inspects a student's device. Everything here reads state that the network the
institution owns inherently has -- DHCP leases, ARP, HTTP source addresses.
"""
