"""Triage logic shared by the Triage agent and the evaluation scripts.

rubric     taxonomy, severity table and investigation depth (requirements spec)
inventory  the asset inventory: hosts, accounts, approved activity
features   inventory lookups, the rules, model features, provisional severity, routing
model      the trained triage model and its decision rule
"""
