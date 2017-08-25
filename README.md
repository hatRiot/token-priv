# Abusing Token Privileges For EoP

August 2017
Bryan Alexander (@dronesec)
Stephen Breen (@breenmachine)

This repository contains all code and a Phrack-style paper on research into abusing token privileges for escalation of privilege.  Please feel free to ping us with questions, ideas, insults, or bugs. 

This repository is organized into three parts:
* lib/, which contains auxiliary scripts (for now just the pykd token script)
* poptoke/, which is the main bulk of the code.  It's organized as a project, but should be noted, and stressed, that it's NOT going to compile and give you shells as is.  It's an amalgam of proof of concepts and portable functions for use in your own bugs and edification, and meant only as a reference guide.  Don't submit issues for "fixing" it, please.
* phrack_token_eop_1.0.txt, complimentary paper on the topic and our findings.
