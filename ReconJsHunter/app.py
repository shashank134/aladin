"""
ReconHunter Web Interface
Flask-based web UI for viewing and running reconnaissance scans with 3-phase modular workflow.
"""

import os
import json
import asyncio
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_from_directory, redirect, url_for

from src.core.config import get_default_config
from src.core.normalizer import URLNormalizer
from src.core.logger import set_silent
from src.recon_engine import ReconEngine
from src.pipelines.recon.runner import ReconRunner
from src.pipelines.js_filter.runner import JsFilterRunner
from src.pipelines.js_analysis.runner import JsAnalysisRunner
from src.services.datastore import DataStore
from src.models import ReconResult, JsFilterResult, JsAnalysisResult

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'reconhunter-dev-key')

OUTPUT_DIR = 'recon_output'
os.makedirs(OUTPUT_DIR, exist_ok=True)

datastore = DataStore(OUTPUT_DIR)

MAIN_TEMPLATE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconHunter - Bug Bounty Reconnaissance</title>
    <style>
        :root {
            --bg-primary: #050810;
            --bg-secondary: #0a0f18;
            --bg-tertiary: #111827;
            --bg-card: #0d1320;
            --text-primary: #f0f4f8;
            --text-secondary: #8b9cb3;
            --accent-blue: #3b82f6;
            --accent-cyan: #06d6e0;
            --accent-green: #10b981;
            --accent-yellow: #fbbf24;
            --accent-red: #f43f5e;
            --accent-purple: #a855f7;
            --accent-orange: #f97316;
            --accent-pink: #ec4899;
            --border-color: #1e293b;
            --glow-blue: 0 0 30px rgba(59, 130, 246, 0.5), 0 0 60px rgba(59, 130, 246, 0.3);
            --glow-cyan: 0 0 30px rgba(6, 214, 224, 0.5), 0 0 60px rgba(6, 214, 224, 0.3);
            --glow-purple: 0 0 30px rgba(168, 85, 247, 0.5), 0 0 60px rgba(168, 85, 247, 0.3);
            --glow-red: 0 0 20px rgba(244, 63, 94, 0.6), 0 0 40px rgba(244, 63, 94, 0.4);
            --glow-yellow: 0 0 20px rgba(251, 191, 36, 0.6), 0 0 40px rgba(251, 191, 36, 0.3);
            --gradient-neon: linear-gradient(135deg, #06d6e0 0%, #3b82f6 25%, #a855f7 50%, #ec4899 75%, #f43f5e 100%);
            --gradient-cyber: linear-gradient(135deg, #0ea5e9 0%, #8b5cf6 50%, #d946ef 100%);
            --gradient-fire: linear-gradient(135deg, #f43f5e 0%, #f97316 50%, #fbbf24 100%);
            --gradient-matrix: linear-gradient(135deg, #10b981 0%, #06d6e0 100%);
            --glass-bg: rgba(13, 19, 32, 0.7);
            --glass-border: rgba(255, 255, 255, 0.08);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            background-image: 
                radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(6, 214, 224, 0.05) 0%, transparent 60%);
            background-attachment: fixed;
        }
        
        .header {
            background: linear-gradient(180deg, rgba(10, 15, 24, 0.95) 0%, rgba(5, 8, 16, 0.98) 100%);
            padding: 50px 20px 40px;
            text-align: center;
            border-bottom: 1px solid var(--glass-border);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-neon);
            background-size: 300% 100%;
            animation: gradientFlow 4s ease infinite;
        }
        
        .header::after {
            content: '';
            position: absolute;
            inset: 0;
            background-image: 
                linear-gradient(rgba(6, 214, 224, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(6, 214, 224, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: gridMove 20s linear infinite;
            pointer-events: none;
        }
        
        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }
        
        @keyframes gradientFlow {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        
        .header h1 {
            font-size: 3.5rem;
            font-weight: 800;
            background: var(--gradient-neon);
            background-size: 300% 100%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
            letter-spacing: -1px;
            animation: titleGlow 3s ease-in-out infinite, gradientFlow 5s ease infinite;
            text-shadow: 0 0 80px rgba(6, 214, 224, 0.5);
            position: relative;
            z-index: 1;
        }
        
        @keyframes titleGlow {
            0%, 100% { 
                filter: drop-shadow(0 0 20px rgba(6, 214, 224, 0.4)) drop-shadow(0 0 40px rgba(59, 130, 246, 0.3));
            }
            50% { 
                filter: drop-shadow(0 0 30px rgba(168, 85, 247, 0.5)) drop-shadow(0 0 60px rgba(236, 72, 153, 0.4));
            }
        }
        
        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
            font-weight: 500;
            position: relative;
            z-index: 1;
            letter-spacing: 0.5px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        .scan-form {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 32px;
            margin-bottom: 30px;
            box-shadow: 
                0 8px 32px rgba(0, 0, 0, 0.4),
                inset 0 0 0 1px rgba(255, 255, 255, 0.05);
            position: relative;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .scan-form::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(6, 214, 224, 0.5), transparent);
        }
        
        .scan-form:hover {
            border-color: rgba(6, 214, 224, 0.3);
            box-shadow: 
                0 12px 48px rgba(0, 0, 0, 0.5),
                0 0 0 1px rgba(6, 214, 224, 0.2),
                inset 0 0 0 1px rgba(255, 255, 255, 0.08);
        }
        
        .form-group {
            margin-bottom: 24px;
            position: relative;
            z-index: 1;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 12px;
            color: var(--text-primary);
            font-weight: 600;
            font-size: 0.95rem;
            letter-spacing: 0.3px;
        }
        
        .form-group input[type="text"] {
            width: 100%;
            padding: 18px 24px;
            background: rgba(17, 24, 39, 0.8);
            border: 2px solid rgba(30, 41, 59, 0.8);
            border-radius: 14px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .form-group input[type="text"]:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 
                0 0 0 4px rgba(6, 214, 224, 0.15),
                0 0 30px rgba(6, 214, 224, 0.2);
            background: rgba(17, 24, 39, 0.95);
        }
        
        .form-group input[type="text"]::placeholder {
            color: var(--text-secondary);
        }
        
        .btn {
            padding: 16px 28px;
            border: none;
            border-radius: 14px;
            font-size: 0.95rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: inline-flex;
            align-items: center;
            gap: 10px;
            position: relative;
            overflow: hidden;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-primary {
            background: var(--gradient-cyber);
            color: #fff;
            box-shadow: 
                0 4px 20px rgba(59, 130, 246, 0.4),
                0 0 0 1px rgba(139, 92, 246, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-3px) scale(1.02);
            box-shadow: 
                0 8px 30px rgba(59, 130, 246, 0.5),
                0 0 40px rgba(139, 92, 246, 0.3);
        }
        
        .btn-primary:disabled {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .btn-secondary {
            background: rgba(17, 24, 39, 0.8);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        
        .btn-secondary:hover:not(:disabled) {
            border-color: var(--accent-cyan);
            background: rgba(6, 214, 224, 0.1);
            box-shadow: 0 0 20px rgba(6, 214, 224, 0.2);
        }
        
        .btn-secondary:disabled {
            color: var(--text-secondary);
            cursor: not-allowed;
        }
        
        .btn-full {
            background: var(--gradient-neon);
            background-size: 200% 100%;
            color: #fff;
            padding: 18px 36px;
            font-size: 1rem;
            animation: gradientShift 3s ease infinite;
            box-shadow: 
                0 4px 20px rgba(6, 214, 224, 0.4),
                0 0 0 1px rgba(168, 85, 247, 0.3);
        }
        
        .btn-full:hover {
            transform: translateY(-3px) scale(1.02);
            box-shadow: 
                0 8px 35px rgba(6, 214, 224, 0.5),
                0 0 50px rgba(168, 85, 247, 0.3);
        }
        
        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        
        .status-message {
            padding: 16px 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: none;
            font-weight: 500;
        }
        
        .status-message.error {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            display: block;
        }
        
        .status-message.success {
            background: rgba(34, 197, 94, 0.15);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            display: block;
        }
        
        .status-message.loading {
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid var(--accent-blue);
            color: var(--accent-blue);
            display: block;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid var(--accent-blue);
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.8s linear infinite;
            margin-right: 12px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .pipeline-section {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 36px;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        
        .pipeline-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--gradient-cyber);
            background-size: 200% 100%;
            animation: gradientShift 4s ease infinite;
        }
        
        .pipeline-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
        }
        
        .pipeline-header h2 {
            font-size: 1.5rem;
            font-weight: 700;
            background: var(--gradient-matrix);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .pipeline-steps {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
        }
        
        .pipeline-step {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(13, 19, 32, 0.95) 100%);
            border: 2px solid rgba(30, 41, 59, 0.6);
            border-radius: 18px;
            padding: 28px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            animation: floatSubtle 6s ease-in-out infinite;
        }
        
        .pipeline-step:nth-child(2) { animation-delay: -2s; }
        .pipeline-step:nth-child(3) { animation-delay: -4s; }
        
        @keyframes floatSubtle {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-6px); }
        }
        
        .pipeline-step::before {
            content: '';
            position: absolute;
            inset: -2px;
            background: linear-gradient(135deg, transparent, rgba(6, 214, 224, 0.3), transparent);
            border-radius: 20px;
            opacity: 0;
            transition: opacity 0.4s;
            z-index: -1;
        }
        
        .pipeline-step:hover::before {
            opacity: 1;
        }
        
        .pipeline-step:hover {
            transform: translateY(-8px);
            border-color: rgba(6, 214, 224, 0.5);
            box-shadow: 
                0 12px 40px rgba(0, 0, 0, 0.4),
                0 0 30px rgba(6, 214, 224, 0.2);
        }
        
        .pipeline-step.active {
            border-color: var(--accent-cyan);
            box-shadow: 
                0 0 30px rgba(6, 214, 224, 0.3),
                0 0 60px rgba(6, 214, 224, 0.15);
        }
        
        .pipeline-step.completed {
            border-color: var(--accent-green);
            box-shadow: 0 0 25px rgba(16, 185, 129, 0.3);
        }
        
        .pipeline-step.running {
            border-color: var(--accent-yellow);
            box-shadow: 0 0 25px rgba(251, 191, 36, 0.3);
            animation: floatSubtle 6s ease-in-out infinite, runningPulse 2s ease-in-out infinite;
        }
        
        @keyframes runningPulse {
            0%, 100% { box-shadow: 0 0 25px rgba(251, 191, 36, 0.3); }
            50% { box-shadow: 0 0 40px rgba(251, 191, 36, 0.5), 0 0 60px rgba(251, 191, 36, 0.2); }
        }
        
        .step-number {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            background: linear-gradient(135deg, rgba(6, 214, 224, 0.2) 0%, rgba(59, 130, 246, 0.2) 100%);
            border: 2px solid rgba(6, 214, 224, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 1.1rem;
            margin-bottom: 18px;
            color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(6, 214, 224, 0.2);
        }
        
        .pipeline-step.completed .step-number {
            background: var(--gradient-matrix);
            border-color: var(--accent-green);
            color: #fff;
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.4);
        }
        
        .pipeline-step.running .step-number {
            background: linear-gradient(135deg, #fbbf24 0%, #f97316 100%);
            border-color: var(--accent-yellow);
            color: #000;
            box-shadow: 0 0 20px rgba(251, 191, 36, 0.4);
            animation: pulseGlow 1.5s ease-in-out infinite;
        }
        
        @keyframes pulseGlow {
            0%, 100% { box-shadow: 0 0 20px rgba(251, 191, 36, 0.4); }
            50% { box-shadow: 0 0 35px rgba(251, 191, 36, 0.7); }
        }
        
        .step-title {
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 10px;
            color: var(--text-primary);
        }
        
        .step-description {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 18px;
            line-height: 1.6;
        }
        
        .step-status {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.85rem;
            margin-bottom: 16px;
            padding: 10px 14px;
            background: rgba(5, 8, 16, 0.6);
            border-radius: 10px;
            border: 1px solid rgba(30, 41, 59, 0.5);
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--text-secondary);
        }
        
        .status-dot.pending { background: var(--text-secondary); }
        .status-dot.running { 
            background: var(--accent-yellow); 
            animation: statusPulse 1s infinite;
            box-shadow: 0 0 10px rgba(251, 191, 36, 0.6);
        }
        .status-dot.completed { 
            background: var(--accent-green);
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.6);
        }
        .status-dot.error { 
            background: var(--accent-red);
            box-shadow: 0 0 10px rgba(244, 63, 94, 0.6);
        }
        
        @keyframes statusPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(1.2); }
        }
        
        .step-stats {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-top: 14px;
        }
        
        .step-stats span {
            display: block;
            margin-bottom: 6px;
        }
        
        .step-stats .highlight {
            color: var(--accent-cyan);
            font-weight: 700;
            text-shadow: 0 0 10px rgba(6, 214, 224, 0.3);
        }
        
        .results-section {
            display: none;
            margin-bottom: 30px;
        }
        
        .results-section.active {
            display: block;
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .results-header h2 {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(13, 19, 32, 0.95) 100%);
            border: 1px solid rgba(30, 41, 59, 0.6);
            border-radius: 16px;
            padding: 24px 20px;
            text-align: center;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-6px) scale(1.02);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }
        
        .stat-card:hover::before {
            opacity: 1;
        }
        
        .stat-card .stat-icon {
            font-size: 2rem;
            margin-bottom: 8px;
            display: block;
        }
        
        .stat-card .number {
            font-size: 2.8rem;
            font-weight: 800;
            margin-bottom: 6px;
            line-height: 1;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .stat-card.blue { border-color: rgba(59, 130, 246, 0.3); }
        .stat-card.blue::before { background: linear-gradient(90deg, #3b82f6, #60a5fa); }
        .stat-card.blue:hover { border-color: rgba(59, 130, 246, 0.6); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(59, 130, 246, 0.2); }
        .stat-card.blue .number { 
            background: linear-gradient(135deg, #3b82f6, #60a5fa); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent;
            background-clip: text; 
        }
        
        .stat-card.cyan { border-color: rgba(6, 214, 224, 0.3); }
        .stat-card.cyan::before { background: linear-gradient(90deg, #06d6e0, #67e8f9); }
        .stat-card.cyan:hover { border-color: rgba(6, 214, 224, 0.6); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(6, 214, 224, 0.2); }
        .stat-card.cyan .number { 
            background: linear-gradient(135deg, #06d6e0, #67e8f9); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent;
            background-clip: text; 
        }
        
        .stat-card.green { border-color: rgba(16, 185, 129, 0.3); }
        .stat-card.green::before { background: linear-gradient(90deg, #10b981, #34d399); }
        .stat-card.green:hover { border-color: rgba(16, 185, 129, 0.6); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(16, 185, 129, 0.2); }
        .stat-card.green .number { 
            background: linear-gradient(135deg, #10b981, #34d399); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent;
            background-clip: text; 
        }
        
        .stat-card.yellow { border-color: rgba(251, 191, 36, 0.3); }
        .stat-card.yellow::before { background: linear-gradient(90deg, #fbbf24, #fcd34d); }
        .stat-card.yellow:hover { border-color: rgba(251, 191, 36, 0.6); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(251, 191, 36, 0.2); }
        .stat-card.yellow .number { 
            background: linear-gradient(135deg, #fbbf24, #fcd34d); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent;
            background-clip: text; 
        }
        
        .stat-card.red { border-color: rgba(244, 63, 94, 0.3); }
        .stat-card.red::before { background: linear-gradient(90deg, #f43f5e, #fb7185); }
        .stat-card.red:hover { border-color: rgba(244, 63, 94, 0.6); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(244, 63, 94, 0.2); }
        .stat-card.red .number { 
            background: linear-gradient(135deg, #f43f5e, #fb7185); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent;
            background-clip: text; 
        }
        
        .stat-card.purple { border-color: rgba(168, 85, 247, 0.3); }
        .stat-card.purple::before { background: linear-gradient(90deg, #a855f7, #c084fc); }
        .stat-card.purple:hover { border-color: rgba(168, 85, 247, 0.6); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4), 0 0 30px rgba(168, 85, 247, 0.2); }
        .stat-card.purple .number { 
            background: linear-gradient(135deg, #a855f7, #c084fc); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent;
            background-clip: text; 
        }
        
        .tabs-container {
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        .tabs {
            display: flex;
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(13, 19, 32, 0.95) 100%);
            border-bottom: 1px solid var(--glass-border);
            overflow-x: auto;
        }
        
        .tab {
            padding: 18px 28px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            white-space: nowrap;
            border-bottom: 3px solid transparent;
            position: relative;
        }
        
        .tab:hover {
            color: var(--text-primary);
            background: rgba(6, 214, 224, 0.08);
        }
        
        .tab.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
            background: linear-gradient(180deg, rgba(6, 214, 224, 0.12) 0%, transparent 100%);
            text-shadow: 0 0 20px rgba(6, 214, 224, 0.4);
        }
        
        .tab-content {
            display: none;
            padding: 24px;
            max-height: 500px;
            overflow-y: auto;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .domain-group {
            margin-bottom: 20px;
        }
        
        .domain-header {
            font-weight: 600;
            color: var(--accent-cyan);
            padding: 12px 16px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .domain-header .count {
            background: var(--bg-primary);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        .url-list {
            list-style: none;
        }
        
        .url-list li {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            transition: all 0.2s;
        }
        
        .js-url-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }
        
        .js-url-link {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .analyze-single-btn {
            padding: 6px 12px;
            background: var(--accent-purple);
            border: none;
            border-radius: 6px;
            color: #fff;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
        }
        
        .analyze-single-btn:hover {
            background: #9333ea;
            transform: scale(1.05);
        }
        
        .analyze-single-btn:disabled {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: not-allowed;
            transform: none;
        }
        
        .analyze-single-btn.loading {
            background: var(--accent-blue);
        }
        
        .url-list li:last-child {
            border-bottom: none;
        }
        
        .url-list li:hover {
            background: var(--bg-tertiary);
        }
        
        .url-list a {
            color: var(--accent-cyan);
            text-decoration: none;
        }
        
        .url-list a:hover {
            text-decoration: underline;
        }
        
        .js-category {
            margin-bottom: 24px;
        }
        
        .js-category-header {
            font-weight: 600;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .js-category-header.internal {
            background: rgba(34, 197, 94, 0.15);
            color: var(--accent-green);
        }
        
        .js-category-header.external {
            background: rgba(139, 92, 246, 0.15);
            color: var(--accent-purple);
        }
        
        .finding-card {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.8) 0%, rgba(13, 19, 32, 0.9) 100%);
            border: 1px solid rgba(30, 41, 59, 0.6);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 14px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            border-left: 4px solid transparent;
        }
        
        .finding-card:hover {
            transform: translateY(-4px) translateX(4px);
            box-shadow: 
                0 12px 40px rgba(0, 0, 0, 0.4),
                0 0 20px rgba(6, 214, 224, 0.1);
            border-color: rgba(6, 214, 224, 0.4);
        }
        
        .finding-card.high-priority {
            border-left-color: var(--accent-red);
        }
        
        .finding-card.medium-priority {
            border-left-color: var(--accent-yellow);
        }
        
        .finding-card.low-priority {
            border-left-color: var(--accent-green);
        }
        
        .finding-header {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }
        
        .finding-card .badge {
            display: inline-flex;
            align-items: center;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .finding-card .badge.high { 
            background: linear-gradient(135deg, #f43f5e 0%, #dc2626 100%);
            color: #fff; 
            animation: highBadgePulse 2s ease-in-out infinite;
            box-shadow: 0 0 15px rgba(244, 63, 94, 0.5);
        }
        
        @keyframes highBadgePulse {
            0%, 100% { 
                box-shadow: 0 0 15px rgba(244, 63, 94, 0.5);
                transform: scale(1);
            }
            50% { 
                box-shadow: 0 0 25px rgba(244, 63, 94, 0.8), 0 0 40px rgba(244, 63, 94, 0.4);
                transform: scale(1.02);
            }
        }
        
        .finding-card .badge.medium { 
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            color: #000; 
            box-shadow: 0 0 12px rgba(251, 191, 36, 0.4);
            animation: mediumBadgeGlow 3s ease-in-out infinite;
        }
        
        @keyframes mediumBadgeGlow {
            0%, 100% { box-shadow: 0 0 12px rgba(251, 191, 36, 0.4); }
            50% { box-shadow: 0 0 20px rgba(251, 191, 36, 0.6); }
        }
        
        .finding-card .badge.low { 
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: #fff; 
        }
        
        .finding-card .category-badge {
            background: linear-gradient(135deg, #a855f7 0%, #7c3aed 100%);
            color: #fff;
        }
        
        .finding-card .type {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .finding-card .value {
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            background: rgba(5, 8, 16, 0.8);
            padding: 14px 18px;
            border-radius: 10px;
            margin: 12px 0;
            word-break: break-all;
            font-size: 0.85rem;
            border: 1px solid rgba(30, 41, 59, 0.6);
            transition: all 0.3s;
        }
        
        .finding-card:hover .value {
            border-color: rgba(6, 214, 224, 0.3);
            background: rgba(5, 8, 16, 0.95);
        }
        
        .finding-card .source {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        
        .finding-card .source a {
            color: var(--accent-cyan);
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .finding-card .source a:hover {
            text-decoration: underline;
            text-shadow: 0 0 10px rgba(6, 214, 224, 0.5);
        }
        
        .findings-category {
            margin-bottom: 18px;
            border: 1px solid rgba(30, 41, 59, 0.6);
            border-radius: 16px;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .findings-category:hover {
            border-color: rgba(6, 214, 224, 0.3);
        }
        
        .findings-category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 24px;
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.95) 0%, rgba(13, 19, 32, 0.98) 100%);
            cursor: pointer;
            user-select: none;
            transition: all 0.3s;
            position: relative;
        }
        
        .findings-category-header::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background: var(--gradient-cyber);
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .findings-category.expanded .findings-category-header::before {
            opacity: 1;
        }
        
        .findings-category-header:hover {
            background: linear-gradient(135deg, rgba(6, 214, 224, 0.08) 0%, rgba(168, 85, 247, 0.05) 100%);
        }
        
        .findings-category-header .category-title {
            display: flex;
            align-items: center;
            gap: 14px;
            font-weight: 700;
            font-size: 1rem;
        }
        
        .findings-category-header .category-icon {
            font-size: 1.4rem;
        }
        
        .findings-category-header .category-stats {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .findings-category-header .stat-badge {
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
        }
        
        .findings-category-header .stat-badge.count {
            background: rgba(6, 214, 224, 0.15);
            color: var(--accent-cyan);
            border: 1px solid rgba(6, 214, 224, 0.3);
        }
        
        .findings-category-header .stat-badge.high-count {
            background: rgba(244, 63, 94, 0.2);
            color: #fb7185;
            border: 1px solid rgba(244, 63, 94, 0.4);
            animation: highCountPulse 2s ease-in-out infinite;
        }
        
        @keyframes highCountPulse {
            0%, 100% { box-shadow: 0 0 0 rgba(244, 63, 94, 0); }
            50% { box-shadow: 0 0 15px rgba(244, 63, 94, 0.4); }
        }
        
        .findings-category-header .stat-badge.medium-count {
            background: rgba(251, 191, 36, 0.2);
            color: #fcd34d;
            border: 1px solid rgba(251, 191, 36, 0.4);
        }
        
        .findings-category-header .chevron {
            transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            color: var(--accent-cyan);
            font-size: 1.2rem;
        }
        
        .findings-category.expanded .chevron {
            transform: rotate(180deg);
        }
        
        .findings-category-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s cubic-bezier(0.4, 0, 0.2, 1);
            background: rgba(5, 8, 16, 0.5);
        }
        
        .findings-category.expanded .findings-category-content {
            max-height: 3000px;
        }
        
        .findings-category-inner {
            padding: 20px;
        }
        
        .category-color-CREDENTIALS { border-left: 5px solid var(--accent-red); }
        .category-color-TOKENS_SECRETS { border-left: 5px solid var(--accent-red); }
        .category-color-API_KEYS { border-left: 5px solid var(--accent-red); }
        .category-color-DATABASE { border-left: 5px solid var(--accent-red); }
        .category-color-AUTH_SESSION { border-left: 5px solid var(--accent-orange); }
        .category-color-BUG_BOUNTY_SIGNALS { border-left: 5px solid var(--accent-orange); }
        .category-color-SECURITY_WEAKNESS { border-left: 5px solid var(--accent-orange); }
        .category-color-INTERNAL_REFERENCES { border-left: 5px solid var(--accent-yellow); }
        .category-color-INTERNAL_PATHS { border-left: 5px solid var(--accent-yellow); }
        .category-color-NETWORK_INFRA { border-left: 5px solid var(--accent-yellow); }
        .category-color-CLOUD_DATA { border-left: 5px solid var(--accent-purple); }
        .category-color-SENSITIVE_CONFIG { border-left: 5px solid var(--accent-purple); }
        .category-color-BUSINESS_LOGIC { border-left: 5px solid var(--accent-purple); }
        .category-color-DEBUG_ARTIFACTS { border-left: 5px solid var(--accent-cyan); }
        .category-color-FRONTEND_FRAMEWORK { border-left: 5px solid var(--accent-cyan); }
        .category-color-PRIVACY_DATA { border-left: 5px solid var(--accent-blue); }
        .category-color-FILE_STORAGE { border-left: 5px solid var(--accent-blue); }
        .category-color-PROTOCOL_COMM { border-left: 5px solid var(--accent-green); }
        .category-color-UUIDS_IDENTIFIERS { border-left: 5px solid var(--accent-pink); }
        .category-color-URLS { border-left: 5px solid var(--accent-cyan); }
        .category-color-EMAILS { border-left: 5px solid var(--accent-blue); }
        
        .category-color-CREDENTIALS .findings-category-header,
        .category-color-TOKENS_SECRETS .findings-category-header,
        .category-color-API_KEYS .findings-category-header,
        .category-color-DATABASE .findings-category-header {
            background: linear-gradient(135deg, rgba(244, 63, 94, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        .category-color-AUTH_SESSION .findings-category-header,
        .category-color-BUG_BOUNTY_SIGNALS .findings-category-header,
        .category-color-SECURITY_WEAKNESS .findings-category-header {
            background: linear-gradient(135deg, rgba(249, 115, 22, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        .category-color-INTERNAL_REFERENCES .findings-category-header,
        .category-color-INTERNAL_PATHS .findings-category-header,
        .category-color-NETWORK_INFRA .findings-category-header {
            background: linear-gradient(135deg, rgba(251, 191, 36, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        .category-color-CLOUD_DATA .findings-category-header,
        .category-color-SENSITIVE_CONFIG .findings-category-header,
        .category-color-BUSINESS_LOGIC .findings-category-header {
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        .category-color-DEBUG_ARTIFACTS .findings-category-header,
        .category-color-FRONTEND_FRAMEWORK .findings-category-header {
            background: linear-gradient(135deg, rgba(6, 214, 224, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        .category-color-PRIVACY_DATA .findings-category-header,
        .category-color-FILE_STORAGE .findings-category-header {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        .category-color-PROTOCOL_COMM .findings-category-header {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(13, 19, 32, 0.98) 100%);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(15px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-15px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        
        @keyframes borderGlow {
            0%, 100% { 
                border-color: rgba(6, 214, 224, 0.3);
                box-shadow: 0 0 20px rgba(6, 214, 224, 0.1);
            }
            50% { 
                border-color: rgba(168, 85, 247, 0.4);
                box-shadow: 0 0 30px rgba(168, 85, 247, 0.2);
            }
        }
        
        .findings-category {
            animation: fadeIn 0.4s ease-out forwards;
            opacity: 0;
        }
        
        .findings-category:nth-child(1) { animation-delay: 0.05s; }
        .findings-category:nth-child(2) { animation-delay: 0.1s; }
        .findings-category:nth-child(3) { animation-delay: 0.15s; }
        .findings-category:nth-child(4) { animation-delay: 0.2s; }
        .findings-category:nth-child(5) { animation-delay: 0.25s; }
        .findings-category:nth-child(6) { animation-delay: 0.3s; }
        .findings-category:nth-child(7) { animation-delay: 0.35s; }
        .findings-category:nth-child(8) { animation-delay: 0.4s; }
        .findings-category:nth-child(9) { animation-delay: 0.45s; }
        .findings-category:nth-child(10) { animation-delay: 0.5s; }
        
        .results-section {
            animation: fadeIn 0.5s ease-out;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        
        .reports-section {
            margin-top: 30px;
        }
        
        .reports-section h2 {
            margin-bottom: 20px;
            font-size: 1.3rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .reports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
        }
        
        .report-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s;
        }
        
        .report-card:hover {
            border-color: var(--accent-blue);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }
        
        .report-card h3 {
            color: var(--accent-cyan);
            margin-bottom: 8px;
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .report-card .meta {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 16px;
        }
        
        .report-card .actions {
            display: flex;
            gap: 10px;
        }
        
        .report-card .actions a {
            padding: 10px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .report-card .actions a:hover {
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: #fff;
        }
        
        footer {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--glass-border);
            margin-top: 50px;
            background: linear-gradient(180deg, transparent 0%, rgba(6, 214, 224, 0.03) 100%);
            position: relative;
        }
        
        footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 200px;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(6, 214, 224, 0.5), transparent);
        }
        
        @media (max-width: 900px) {
            .pipeline-steps {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ReconHunter</h1>
        <p>Professional Bug Bounty Reconnaissance Tool - 3-Phase Modular Workflow</p>
    </div>
    
    <div class="container">
        <div class="scan-form">
            <div class="form-group">
                <label for="target">Target Domain or URL</label>
                <input type="text" id="target" name="target" 
                       placeholder="Enter domain (e.g., example.com) or URL" required>
            </div>
            
            <div id="globalStatus" class="status-message"></div>
        </div>
        
        <div class="scan-form" style="margin-bottom: 20px;">
            <div class="form-group" style="margin-bottom: 16px;">
                <label for="singleJsUrl">Analyze Single JavaScript URL (Manual)</label>
                <div style="display: flex; gap: 12px;">
                    <input type="text" id="singleJsUrl" 
                           placeholder="Paste any JavaScript URL (e.g., https://example.com/app.js)" 
                           style="flex: 1;">
                    <button class="btn btn-primary" id="analyzeSingleUrlBtn" onclick="analyzeManualUrl()">
                        Analyze URL
                    </button>
                </div>
            </div>
            <div id="singleUrlStatus" class="status-message"></div>
            <div id="singleUrlFindings" style="margin-top: 16px;"></div>
        </div>
        
        <div class="pipeline-section">
            <div class="pipeline-header">
                <h2>Pipeline Workflow</h2>
                <button class="btn btn-full" id="runFullPipeline" onclick="runFullPipeline()">
                    Run Full Pipeline
                </button>
            </div>
            
            <div class="pipeline-steps">
                <div class="pipeline-step" id="step1">
                    <div class="step-number">1</div>
                    <div class="step-title">Reconnaissance</div>
                    <div class="step-description">
                        Collect URLs from Wayback, URLScan, AlienVault, CommonCrawl, and search engines.
                    </div>
                    <div class="step-status">
                        <span class="status-dot pending" id="step1Dot"></span>
                        <span id="step1Status">Not started</span>
                    </div>
                    <div class="step-stats" id="step1Stats"></div>
                    <button class="btn btn-secondary" id="runRecon" onclick="runRecon()">
                        Run Recon
                    </button>
                </div>
                
                <div class="pipeline-step" id="step2">
                    <div class="step-number">2</div>
                    <div class="step-title">Filter JavaScript</div>
                    <div class="step-description">
                        Extract and categorize JavaScript URLs into internal and external.
                    </div>
                    <div class="step-status">
                        <span class="status-dot pending" id="step2Dot"></span>
                        <span id="step2Status">Not started</span>
                    </div>
                    <div class="step-stats" id="step2Stats"></div>
                    <button class="btn btn-secondary" id="runFilter" onclick="runFilterJs()" disabled>
                        Filter JS
                    </button>
                </div>
                
                <div class="pipeline-step" id="step3">
                    <div class="step-number">3</div>
                    <div class="step-title">Analyze JavaScript</div>
                    <div class="step-description">
                        Deep static analysis for secrets, API keys, credentials, and endpoints.
                    </div>
                    <div class="step-status">
                        <span class="status-dot pending" id="step3Dot"></span>
                        <span id="step3Status">Not started</span>
                    </div>
                    <div class="step-stats" id="step3Stats"></div>
                    <button class="btn btn-secondary" id="runAnalysis" onclick="runAnalyzeJs()" disabled>
                        Analyze JS
                    </button>
                </div>
            </div>
        </div>
        
        <div id="resultsSection" class="results-section">
            <div class="results-header">
                <h2>Results</h2>
            </div>
            
            <div class="stats-grid" id="statsGrid">
                <div class="stat-card blue">
                    <div class="number" id="statUrls">0</div>
                    <div class="label">Total URLs</div>
                </div>
                <div class="stat-card cyan">
                    <div class="number" id="statDomains">0</div>
                    <div class="label">Domains</div>
                </div>
                <div class="stat-card purple">
                    <div class="number" id="statJsFiles">0</div>
                    <div class="label">JS Files</div>
                </div>
                <div class="stat-card green">
                    <div class="number" id="statInternalJs">0</div>
                    <div class="label">Internal JS</div>
                </div>
                <div class="stat-card yellow">
                    <div class="number" id="statExternalJs">0</div>
                    <div class="label">External JS</div>
                </div>
                <div class="stat-card red">
                    <div class="number" id="statFindings">0</div>
                    <div class="label">Findings</div>
                </div>
            </div>
            
            <div class="tabs-container">
                <div class="tabs">
                    <button class="tab active" data-tab="urls-tab">URLs by Domain</button>
                    <button class="tab" data-tab="js-tab">JavaScript Files</button>
                    <button class="tab" data-tab="findings-tab">Findings</button>
                </div>
                
                <div id="urls-tab" class="tab-content active">
                    <div id="urlsByDomain"></div>
                </div>
                
                <div id="js-tab" class="tab-content">
                    <div id="jsCategories"></div>
                </div>
                
                <div id="findings-tab" class="tab-content">
                    <div id="findingsList"></div>
                </div>
            </div>
        </div>
        
        <div class="reports-section">
            <h2>Previous Reports</h2>
            <div class="reports-grid" id="reportsGrid">
                {% if reports %}
                    {% for report in reports %}
                    <div class="report-card">
                        <h3>{{ report.domain }}</h3>
                        <div class="meta">{{ report.date }}</div>
                        <div class="actions">
                            <a href="/report/{{ report.folder }}/report.html">View HTML</a>
                            <a href="/report/{{ report.folder }}/full_report.json">View JSON</a>
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <div class="empty-state">
                        No reports yet. Start a scan to generate your first report.
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <footer>
        ReconHunter v2.0.0 | 3-Phase Modular Pipeline | For authorized security testing only
    </footer>
    
    <script>
        let currentTarget = '';
        let pipelineState = {
            recon: { status: 'pending', data: null },
            filter: { status: 'pending', data: null },
            analysis: { status: 'pending', data: null }
        };
        
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });
        
        function getTarget() {
            const target = document.getElementById('target').value.trim();
            if (!target) {
                showGlobalStatus('Please enter a target domain', 'error');
                return null;
            }
            return target;
        }
        
        function showGlobalStatus(message, type) {
            const statusDiv = document.getElementById('globalStatus');
            statusDiv.className = 'status-message ' + type;
            if (type === 'loading') {
                statusDiv.innerHTML = '<span class="loading-spinner"></span>' + message;
            } else {
                statusDiv.textContent = message;
            }
        }
        
        function hideGlobalStatus() {
            document.getElementById('globalStatus').className = 'status-message';
        }
        
        function updateStepStatus(step, status, message) {
            const dot = document.getElementById('step' + step + 'Dot');
            const statusText = document.getElementById('step' + step + 'Status');
            const stepDiv = document.getElementById('step' + step);
            
            dot.className = 'status-dot ' + status;
            statusText.textContent = message;
            
            stepDiv.classList.remove('completed', 'running', 'active');
            if (status === 'completed') {
                stepDiv.classList.add('completed');
            } else if (status === 'running') {
                stepDiv.classList.add('running');
            }
        }
        
        function updateStepStats(step, stats) {
            const statsDiv = document.getElementById('step' + step + 'Stats');
            statsDiv.innerHTML = stats;
        }
        
        async function runRecon() {
            const target = getTarget();
            if (!target) return;
            
            currentTarget = target;
            document.getElementById('runRecon').disabled = true;
            updateStepStatus(1, 'running', 'Running...');
            showGlobalStatus('Phase 1: Collecting URLs from all sources...', 'loading');
            
            try {
                const response = await fetch('/api/recon', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    pipelineState.recon = { status: 'completed', data: result.data };
                    updateStepStatus(1, 'completed', 'Completed');
                    updateStepStats(1, `
                        <span><span class="highlight">${result.data.total_urls}</span> URLs found</span>
                        <span><span class="highlight">${Object.keys(result.data.urls_by_domain || {}).length}</span> domains</span>
                        <span>Sources: ${(result.data.sources_used || []).join(', ')}</span>
                    `);
                    
                    document.getElementById('runFilter').disabled = false;
                    displayReconResults(result.data);
                    hideGlobalStatus();
                } else {
                    updateStepStatus(1, 'error', 'Failed');
                    showGlobalStatus('Error: ' + result.error, 'error');
                }
            } catch (error) {
                updateStepStatus(1, 'error', 'Failed');
                showGlobalStatus('Error: ' + error.message, 'error');
            } finally {
                document.getElementById('runRecon').disabled = false;
            }
        }
        
        async function runFilterJs() {
            const target = getTarget();
            if (!target) return;
            
            document.getElementById('runFilter').disabled = true;
            updateStepStatus(2, 'running', 'Running...');
            showGlobalStatus('Phase 2: Extracting JavaScript URLs...', 'loading');
            
            try {
                const response = await fetch('/api/filter-js', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    pipelineState.filter = { status: 'completed', data: result.data };
                    updateStepStatus(2, 'completed', 'Completed');
                    updateStepStats(2, `
                        <span><span class="highlight">${result.data.total_js_urls}</span> JS files</span>
                        <span><span class="highlight">${(result.data.internal_js || []).length}</span> internal</span>
                        <span><span class="highlight">${(result.data.external_js || []).length}</span> external</span>
                    `);
                    
                    document.getElementById('runAnalysis').disabled = false;
                    displayFilterResults(result.data);
                    hideGlobalStatus();
                } else {
                    updateStepStatus(2, 'error', 'Failed');
                    showGlobalStatus('Error: ' + result.error, 'error');
                }
            } catch (error) {
                updateStepStatus(2, 'error', 'Failed');
                showGlobalStatus('Error: ' + error.message, 'error');
            } finally {
                document.getElementById('runFilter').disabled = false;
            }
        }
        
        async function runAnalyzeJs() {
            const target = getTarget();
            if (!target) return;
            
            document.getElementById('runAnalysis').disabled = true;
            updateStepStatus(3, 'running', 'Running...');
            showGlobalStatus('Phase 3: Analyzing JavaScript files (this may take a while)...', 'loading');
            
            try {
                const response = await fetch('/api/analyze-js', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    pipelineState.analysis = { status: 'completed', data: result.data };
                    updateStepStatus(3, 'completed', 'Completed');
                    updateStepStats(3, `
                        <span><span class="highlight">${result.data.total_files}</span> files analyzed</span>
                        <span><span class="highlight">${result.data.total_findings}</span> findings</span>
                        <span>High: ${result.data.findings_by_confidence?.high || 0}</span>
                    `);
                    
                    displayAnalysisResults(result.data);
                    showGlobalStatus('All phases completed successfully!', 'success');
                } else {
                    updateStepStatus(3, 'error', 'Failed');
                    showGlobalStatus('Error: ' + result.error, 'error');
                }
            } catch (error) {
                updateStepStatus(3, 'error', 'Failed');
                showGlobalStatus('Error: ' + error.message, 'error');
            } finally {
                document.getElementById('runAnalysis').disabled = false;
            }
        }
        
        async function runFullPipeline() {
            const target = getTarget();
            if (!target) return;
            
            currentTarget = target;
            document.getElementById('runFullPipeline').disabled = true;
            document.getElementById('runRecon').disabled = true;
            document.getElementById('runFilter').disabled = true;
            document.getElementById('runAnalysis').disabled = true;
            
            showGlobalStatus('Running full pipeline...', 'loading');
            
            try {
                const response = await fetch('/api/pipeline', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    if (result.data.recon) {
                        pipelineState.recon = { status: 'completed', data: result.data.recon };
                        updateStepStatus(1, 'completed', 'Completed');
                        updateStepStats(1, `
                            <span><span class="highlight">${result.data.recon.total_urls}</span> URLs</span>
                            <span><span class="highlight">${Object.keys(result.data.recon.urls_by_domain || {}).length}</span> domains</span>
                        `);
                        displayReconResults(result.data.recon);
                    }
                    
                    if (result.data.filter) {
                        pipelineState.filter = { status: 'completed', data: result.data.filter };
                        updateStepStatus(2, 'completed', 'Completed');
                        updateStepStats(2, `
                            <span><span class="highlight">${result.data.filter.total_js_urls}</span> JS files</span>
                            <span><span class="highlight">${(result.data.filter.internal_js || []).length}</span> internal</span>
                        `);
                        displayFilterResults(result.data.filter);
                    }
                    
                    if (result.data.analysis) {
                        pipelineState.analysis = { status: 'completed', data: result.data.analysis };
                        updateStepStatus(3, 'completed', 'Completed');
                        updateStepStats(3, `
                            <span><span class="highlight">${result.data.analysis.total_findings}</span> findings</span>
                            <span>High: ${result.data.analysis.findings_by_confidence?.high || 0}</span>
                        `);
                        displayAnalysisResults(result.data.analysis);
                    }
                    
                    showGlobalStatus('Full pipeline completed successfully!', 'success');
                } else {
                    showGlobalStatus('Error: ' + result.error, 'error');
                }
            } catch (error) {
                showGlobalStatus('Error: ' + error.message, 'error');
            } finally {
                document.getElementById('runFullPipeline').disabled = false;
                document.getElementById('runRecon').disabled = false;
                if (pipelineState.recon.status === 'completed') {
                    document.getElementById('runFilter').disabled = false;
                }
                if (pipelineState.filter.status === 'completed') {
                    document.getElementById('runAnalysis').disabled = false;
                }
            }
        }
        
        function displayReconResults(data) {
            document.getElementById('resultsSection').classList.add('active');
            
            document.getElementById('statUrls').textContent = data.total_urls || 0;
            document.getElementById('statDomains').textContent = Object.keys(data.urls_by_domain || {}).length;
            
            const urlsByDomainDiv = document.getElementById('urlsByDomain');
            urlsByDomainDiv.innerHTML = '';
            
            const domains = data.urls_by_domain || {};
            if (Object.keys(domains).length === 0) {
                urlsByDomainDiv.innerHTML = '<div class="empty-state">No URLs found</div>';
                return;
            }
            
            const BATCH_SIZE = 50;
            
            for (const [domain, urls] of Object.entries(domains)) {
                const group = document.createElement('div');
                group.className = 'domain-group';
                
                const header = document.createElement('div');
                header.className = 'domain-header';
                header.innerHTML = `<span>${domain}</span><span class="count">${urls.length} URLs</span>`;
                group.appendChild(header);
                
                const list = document.createElement('ul');
                list.className = 'url-list';
                list.dataset.domain = domain;
                
                let displayedCount = 0;
                
                function renderUrlBatch(startIdx, count) {
                    const endIdx = Math.min(startIdx + count, urls.length);
                    const loadMoreItem = list.querySelector('.load-more-item');
                    for (let i = startIdx; i < endIdx; i++) {
                        const urlObj = urls[i];
                        const li = document.createElement('li');
                        const url = typeof urlObj === 'string' ? urlObj : urlObj.url;
                        li.innerHTML = `<a href="${url}" target="_blank" rel="noopener">${url}</a>`;
                        if (loadMoreItem) {
                            list.insertBefore(li, loadMoreItem);
                        } else {
                            list.appendChild(li);
                        }
                    }
                    return endIdx;
                }
                
                displayedCount = renderUrlBatch(0, BATCH_SIZE);
                
                if (urls.length > BATCH_SIZE) {
                    const loadMoreLi = document.createElement('li');
                    loadMoreLi.className = 'load-more-item';
                    loadMoreLi.innerHTML = `
                        <button class="btn btn-secondary" style="width: 100%; margin: 8px 0;">
                            Load More (${urls.length - displayedCount} remaining)
                        </button>
                    `;
                    loadMoreLi.querySelector('button').addEventListener('click', function() {
                        displayedCount = renderUrlBatch(displayedCount, BATCH_SIZE);
                        if (displayedCount >= urls.length) {
                            loadMoreLi.remove();
                        } else {
                            this.textContent = `Load More (${urls.length - displayedCount} remaining)`;
                        }
                    });
                    list.appendChild(loadMoreLi);
                }
                
                group.appendChild(list);
                urlsByDomainDiv.appendChild(group);
            }
        }
        
        function displayFilterResults(data) {
            document.getElementById('resultsSection').classList.add('active');
            
            const totalJs = data.total_js_urls || 0;
            const internalJs = data.internal_js || [];
            const externalJs = data.external_js || [];
            
            document.getElementById('statJsFiles').textContent = totalJs;
            document.getElementById('statInternalJs').textContent = internalJs.length;
            document.getElementById('statExternalJs').textContent = externalJs.length;
            
            const jsCategoriesDiv = document.getElementById('jsCategories');
            jsCategoriesDiv.innerHTML = '';
            
            const JS_BATCH_SIZE = 100;
            
            function createJsCategory(jsArray, categoryName, headerClass) {
                if (jsArray.length === 0) return null;
                
                const categoryDiv = document.createElement('div');
                categoryDiv.className = 'js-category';
                categoryDiv.innerHTML = `
                    <div class="js-category-header ${headerClass}">
                        <span>${categoryName}</span>
                        <span>${jsArray.length} files</span>
                    </div>
                `;
                
                const list = document.createElement('ul');
                list.className = 'url-list';
                
                let displayedCount = 0;
                
                function renderJsBatch(startIdx, count) {
                    const endIdx = Math.min(startIdx + count, jsArray.length);
                    const loadMoreItem = list.querySelector('.load-more-item');
                    for (let i = startIdx; i < endIdx; i++) {
                        const js = jsArray[i];
                        const li = document.createElement('li');
                        li.className = 'js-url-item';
                        li.innerHTML = `
                            <a href="${js.url}" target="_blank" rel="noopener" class="js-url-link">${js.url}</a>
                            <button class="analyze-single-btn" onclick="analyzeSingleJs('${js.url.replace(/'/g, "\\'")}')">Analyze</button>
                        `;
                        if (loadMoreItem) {
                            list.insertBefore(li, loadMoreItem);
                        } else {
                            list.appendChild(li);
                        }
                    }
                    return endIdx;
                }
                
                displayedCount = renderJsBatch(0, JS_BATCH_SIZE);
                
                if (jsArray.length > JS_BATCH_SIZE) {
                    const loadMoreLi = document.createElement('li');
                    loadMoreLi.className = 'load-more-item';
                    loadMoreLi.innerHTML = `
                        <button class="btn btn-secondary" style="width: 100%; margin: 8px 0;">
                            Load More (${jsArray.length - displayedCount} remaining)
                        </button>
                    `;
                    loadMoreLi.querySelector('button').addEventListener('click', function() {
                        displayedCount = renderJsBatch(displayedCount, JS_BATCH_SIZE);
                        if (displayedCount >= jsArray.length) {
                            loadMoreLi.remove();
                        } else {
                            this.textContent = `Load More (${jsArray.length - displayedCount} remaining)`;
                        }
                    });
                    list.appendChild(loadMoreLi);
                }
                
                categoryDiv.appendChild(list);
                return categoryDiv;
            }
            
            const internalDiv = createJsCategory(internalJs, 'Internal JavaScript', 'internal');
            if (internalDiv) jsCategoriesDiv.appendChild(internalDiv);
            
            const externalDiv = createJsCategory(externalJs, 'External JavaScript', 'external');
            if (externalDiv) jsCategoriesDiv.appendChild(externalDiv);
            
            if (internalJs.length === 0 && externalJs.length === 0) {
                jsCategoriesDiv.innerHTML = '<div class="empty-state">No JavaScript files found</div>';
            }
        }
        
        function displayAnalysisResults(data) {
            document.getElementById('resultsSection').classList.add('active');
            
            document.getElementById('statFindings').textContent = data.total_findings || 0;
            
            const findingsDiv = document.getElementById('findingsList');
            findingsDiv.innerHTML = '';
            
            const filesAnalyzed = data.files_analyzed || [];
            let allFindings = [];
            
            filesAnalyzed.forEach(file => {
                (file.findings || []).forEach(finding => {
                    allFindings.push({
                        ...finding,
                        source_url: file.url
                    });
                });
            });
            
            if (allFindings.length === 0) {
                findingsDiv.innerHTML = '<div class="empty-state">No findings detected</div>';
                return;
            }
            
            const categoryIcons = {
                'CREDENTIALS': '🔑', 'TOKENS_SECRETS': '🎫', 'API_KEYS': '🔐', 'DATABASE': '🗄️',
                'AUTH_SESSION': '🔒', 'BUG_BOUNTY_SIGNALS': '🎯', 'SECURITY_WEAKNESS': '⚠️',
                'INTERNAL_REFERENCES': '🏠', 'INTERNAL_PATHS': '📁', 'NETWORK_INFRA': '🌐',
                'CLOUD_DATA': '☁️', 'SENSITIVE_CONFIG': '⚙️', 'BUSINESS_LOGIC': '💼',
                'DEBUG_ARTIFACTS': '🐛', 'FRONTEND_FRAMEWORK': '📦', 'PRIVACY_DATA': '👤',
                'FILE_STORAGE': '💾', 'PROTOCOL_COMM': '📡', 'UUIDS_IDENTIFIERS': '🆔',
                'URLS': '🔗', 'EMAILS': '📧'
            };
            
            const categoryPriority = ['CREDENTIALS', 'TOKENS_SECRETS', 'API_KEYS', 'DATABASE', 
                'AUTH_SESSION', 'BUG_BOUNTY_SIGNALS', 'SECURITY_WEAKNESS', 'INTERNAL_REFERENCES',
                'INTERNAL_PATHS', 'NETWORK_INFRA', 'CLOUD_DATA', 'SENSITIVE_CONFIG', 'BUSINESS_LOGIC',
                'DEBUG_ARTIFACTS', 'FRONTEND_FRAMEWORK', 'PRIVACY_DATA', 'FILE_STORAGE', 
                'PROTOCOL_COMM', 'UUIDS_IDENTIFIERS', 'URLS', 'EMAILS'];
            
            const groupedFindings = {};
            allFindings.forEach(finding => {
                const cat = finding.category || 'Unknown';
                if (!groupedFindings[cat]) groupedFindings[cat] = [];
                groupedFindings[cat].push(finding);
            });
            
            Object.keys(groupedFindings).forEach(cat => {
                groupedFindings[cat].sort((a, b) => {
                    const order = { high: 0, medium: 1, low: 2 };
                    return (order[a.confidence] || 3) - (order[b.confidence] || 3);
                });
            });
            
            const sortedCategories = Object.keys(groupedFindings).sort((a, b) => {
                const idxA = categoryPriority.indexOf(a);
                const idxB = categoryPriority.indexOf(b);
                return (idxA === -1 ? 999 : idxA) - (idxB === -1 ? 999 : idxB);
            });
            
            function renderFindingCard(finding) {
                const card = document.createElement('div');
                card.className = 'finding-card';
                
                const confidence = finding.confidence || 'low';
                const type = finding.finding_type || finding.type || 'Unknown';
                const value = finding.value || '';
                const context = finding.context || '';
                const sourceUrl = finding.source_url || '';
                const lineNumber = finding.line_number;
                const entropy = finding.entropy;
                
                card.innerHTML = `
                    <div class="finding-header">
                        <span class="badge ${confidence}">${confidence}</span>
                        <span class="type">${type}</span>
                    </div>
                    <div class="value">${escapeHtml(value)}</div>
                    ${context ? `<div class="source">Context: ${escapeHtml(context.substring(0, 100))}${context.length > 100 ? '...' : ''}</div>` : ''}
                    <div class="source">
                        ${lineNumber ? `Line: ${lineNumber} | ` : ''}
                        ${entropy ? `Entropy: ${entropy.toFixed(2)} | ` : ''}
                        ${sourceUrl ? `Source: <a href="${sourceUrl}" target="_blank">${sourceUrl.substring(0, 60)}...</a>` : ''}
                    </div>
                `;
                return card;
            }
            
            let firstHighCategoryExpanded = false;
            sortedCategories.forEach((category, idx) => {
                const findings = groupedFindings[category];
                const highCount = findings.filter(f => f.confidence === 'high').length;
                const mediumCount = findings.filter(f => f.confidence === 'medium').length;
                const icon = categoryIcons[category] || '📋';
                const displayName = category.replace(/_/g, ' ');
                
                const categorySection = document.createElement('div');
                categorySection.className = `findings-category category-color-${category}`;
                if (highCount > 0 && !firstHighCategoryExpanded) {
                    categorySection.classList.add('expanded');
                    firstHighCategoryExpanded = true;
                }
                
                categorySection.innerHTML = `
                    <div class="findings-category-header">
                        <div class="category-title">
                            <span class="category-icon">${icon}</span>
                            <span>${displayName}</span>
                        </div>
                        <div class="category-stats">
                            ${highCount > 0 ? `<span class="stat-badge high-count">${highCount} HIGH</span>` : ''}
                            ${mediumCount > 0 ? `<span class="stat-badge medium-count">${mediumCount} MED</span>` : ''}
                            <span class="stat-badge count">${findings.length} total</span>
                            <span class="chevron">▼</span>
                        </div>
                    </div>
                    <div class="findings-category-content">
                        <div class="findings-category-inner"></div>
                    </div>
                `;
                
                const header = categorySection.querySelector('.findings-category-header');
                header.addEventListener('click', () => {
                    categorySection.classList.toggle('expanded');
                });
                
                const innerDiv = categorySection.querySelector('.findings-category-inner');
                findings.forEach(finding => {
                    innerDiv.appendChild(renderFindingCard(finding));
                });
                
                findingsDiv.appendChild(categorySection);
            });
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        async function analyzeManualUrl() {
            const jsUrl = document.getElementById('singleJsUrl').value.trim();
            const btn = document.getElementById('analyzeSingleUrlBtn');
            const statusDiv = document.getElementById('singleUrlStatus');
            const findingsDiv = document.getElementById('singleUrlFindings');
            
            if (!jsUrl) {
                statusDiv.className = 'status-message error';
                statusDiv.textContent = 'Please enter a JavaScript URL';
                statusDiv.style.display = 'block';
                return;
            }
            
            if (!jsUrl.match(/^https?:\/\//)) {
                statusDiv.className = 'status-message error';
                statusDiv.textContent = 'URL must start with http:// or https://';
                statusDiv.style.display = 'block';
                return;
            }
            
            btn.disabled = true;
            btn.textContent = 'Analyzing...';
            statusDiv.style.display = 'none';
            findingsDiv.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-secondary);">Fetching and analyzing JavaScript file...</div>';
            
            try {
                const response = await fetch('/api/analyze-single-js', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: jsUrl })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    const data = result.data;
                    const fileAnalysis = data.files_analyzed?.[0];
                    const findings = fileAnalysis?.findings || [];
                    const fileSize = fileAnalysis?.file_size || 0;
                    const status = fileAnalysis?.status || 'unknown';
                    
                    if (status === 'failed' || status === 'error') {
                        statusDiv.className = 'status-message error';
                        statusDiv.textContent = 'Failed to fetch: ' + (fileAnalysis?.error || 'Unknown error');
                        statusDiv.style.display = 'block';
                        findingsDiv.innerHTML = '';
                    } else if (findings.length > 0) {
                        statusDiv.className = 'status-message success';
                        statusDiv.textContent = `Found ${findings.length} finding(s) in ${(fileSize/1024).toFixed(1)}KB file`;
                        statusDiv.style.display = 'block';
                        
                        findingsDiv.innerHTML = '';
                        findings.forEach(finding => {
                            const card = document.createElement('div');
                            card.className = 'finding-card';
                            const confidence = finding.confidence || 'low';
                            const category = finding.category || 'Unknown';
                            const type = finding.finding_type || finding.type || 'Unknown';
                            const value = finding.value || '';
                            const context = finding.context || '';
                            const lineNumber = finding.line_number;
                            const entropy = finding.entropy;
                            
                            card.innerHTML = `
                                <div class="finding-header">
                                    <span class="badge ${confidence}">${confidence}</span>
                                    <span class="badge category-badge">${category}</span>
                                    <span class="type">${type}</span>
                                </div>
                                <div class="value">${escapeHtml(value)}</div>
                                ${context ? `<div class="source">Context: ${escapeHtml(context.substring(0, 200))}${context.length > 200 ? '...' : ''}</div>` : ''}
                                <div class="source">
                                    ${lineNumber ? `Line: ${lineNumber}` : ''}
                                    ${entropy ? ` | Entropy: ${entropy.toFixed(2)}` : ''}
                                </div>
                            `;
                            findingsDiv.appendChild(card);
                        });
                    } else {
                        statusDiv.className = 'status-message';
                        statusDiv.style.background = 'rgba(234, 179, 8, 0.15)';
                        statusDiv.style.border = '1px solid var(--accent-yellow)';
                        statusDiv.style.color = 'var(--accent-yellow)';
                        statusDiv.textContent = `No findings in ${(fileSize/1024).toFixed(1)}KB file - this file may be clean or contain obfuscated code`;
                        statusDiv.style.display = 'block';
                        findingsDiv.innerHTML = '';
                    }
                } else {
                    statusDiv.className = 'status-message error';
                    statusDiv.textContent = 'Error: ' + (result.error || 'Unknown error');
                    statusDiv.style.display = 'block';
                    findingsDiv.innerHTML = '';
                }
            } catch (error) {
                statusDiv.className = 'status-message error';
                statusDiv.textContent = 'Network error: ' + error.message;
                statusDiv.style.display = 'block';
                findingsDiv.innerHTML = '';
            }
            
            btn.disabled = false;
            btn.textContent = 'Analyze URL';
        }
        
        async function analyzeSingleJs(jsUrl) {
            const btn = event.target;
            const originalText = btn.textContent;
            
            btn.textContent = 'Analyzing...';
            btn.disabled = true;
            btn.classList.add('loading');
            
            try {
                const response = await fetch('/api/analyze-single-js', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: jsUrl })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    const data = result.data;
                    const findings = data.files_analyzed?.[0]?.findings || [];
                    
                    if (findings.length > 0) {
                        btn.textContent = `${findings.length} found`;
                        btn.style.background = 'var(--accent-green)';
                        
                        displayAnalysisResults(data);
                        
                        alert(`Found ${findings.length} finding(s) in this JavaScript file! Check the Findings section below.`);
                    } else {
                        btn.textContent = 'No findings';
                        btn.style.background = 'var(--text-secondary)';
                    }
                } else {
                    btn.textContent = 'Error';
                    btn.style.background = 'var(--accent-red)';
                    alert('Analysis failed: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                btn.textContent = 'Error';
                btn.style.background = 'var(--accent-red)';
                alert('Error analyzing JavaScript: ' + error.message);
            }
            
            btn.disabled = false;
            btn.classList.remove('loading');
        }
        
        document.getElementById('target').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                checkTargetStatus();
            }
        });
        
        async function checkTargetStatus() {
            const target = getTarget();
            if (!target) return;
            
            try {
                const response = await fetch(`/api/status/${encodeURIComponent(target)}`);
                const result = await response.json();
                
                if (result.success) {
                    const status = result.status;
                    
                    if (status.has_recon) {
                        updateStepStatus(1, 'completed', 'Cached');
                        document.getElementById('runFilter').disabled = false;
                        
                        if (status.recon_data) {
                            displayReconResults(status.recon_data);
                        }
                    }
                    
                    if (status.has_js_urls) {
                        updateStepStatus(2, 'completed', 'Cached');
                        document.getElementById('runAnalysis').disabled = false;
                        
                        if (status.filter_data) {
                            displayFilterResults(status.filter_data);
                        }
                    }
                    
                    if (status.has_findings) {
                        updateStepStatus(3, 'completed', 'Cached');
                        
                        if (status.analysis_data) {
                            displayAnalysisResults(status.analysis_data);
                        }
                    }
                }
            } catch (error) {
                console.log('Could not check target status:', error);
            }
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    reports = get_existing_reports()
    return render_template_string(MAIN_TEMPLATE, reports=reports)


@app.route('/api/recon', methods=['POST'])
def api_recon():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        config = get_default_config()
        runner = ReconRunner(config=config, silent_mode=True, output_dir=OUTPUT_DIR)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(runner.run(target))
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'data': result.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/filter-js', methods=['POST'])
def api_filter_js():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        runner = JsFilterRunner(silent_mode=True, output_dir=OUTPUT_DIR)
        result = runner.run(target)
        
        return jsonify({
            'success': True,
            'data': result.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/analyze-js', methods=['POST'])
def api_analyze_js():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        runner = JsAnalysisRunner(silent_mode=True, output_dir=OUTPUT_DIR)
        result = runner.run(target)
        
        return jsonify({
            'success': True,
            'data': result.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/analyze-single-js', methods=['POST'])
def api_analyze_single_js():
    """Analyze a single JavaScript URL - useful when bulk analysis fails."""
    try:
        data = request.get_json()
        js_url = data.get('url', '').strip()
        
        if not js_url:
            return jsonify({'success': False, 'error': 'No JavaScript URL specified'})
        
        runner = JsAnalysisRunner(silent_mode=True, output_dir=OUTPUT_DIR)
        result = runner.run_from_urls("single_analysis", [js_url])
        
        return jsonify({
            'success': True,
            'data': result.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/pipeline', methods=['POST'])
def api_pipeline():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        config = get_default_config()
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            recon_runner = ReconRunner(config=config, silent_mode=True, output_dir=OUTPUT_DIR)
            recon_result = loop.run_until_complete(recon_runner.run(target))
            
            filter_runner = JsFilterRunner(silent_mode=True, output_dir=OUTPUT_DIR)
            filter_result = filter_runner.run(target, recon_result=recon_result)
            
            analysis_runner = JsAnalysisRunner(silent_mode=True, output_dir=OUTPUT_DIR)
            analysis_result = analysis_runner.run(target, js_filter_result=filter_result)
            
        finally:
            loop.close()
        
        from src.output.html_report import generate_modular_html_report
        try:
            generate_modular_html_report(
                target=target,
                recon_result=recon_result,
                js_filter_result=filter_result,
                js_analysis_result=analysis_result,
                output_dir=OUTPUT_DIR
            )
        except Exception:
            pass
        
        return jsonify({
            'success': True,
            'data': {
                'recon': recon_result.to_dict(),
                'filter': filter_result.to_dict(),
                'analysis': analysis_result.to_dict()
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/status/<path:target>', methods=['GET'])
def api_status(target):
    try:
        target = target.strip()
        normalizer = URLNormalizer()
        normalized_target = normalizer.normalize_domain(target)
        
        status = datastore.get_target_status(normalized_target)
        
        response_data = {
            'success': True,
            'status': status
        }
        
        if status.get('has_recon'):
            recon_result = datastore.load_recon_result(normalized_target)
            if recon_result:
                response_data['status']['recon_data'] = recon_result.to_dict()
        
        if status.get('has_js_urls'):
            filter_result = datastore.load_js_filter_result(normalized_target)
            if filter_result:
                response_data['status']['filter_data'] = filter_result.to_dict()
        
        if status.get('has_findings'):
            analysis_result = datastore.load_js_analysis_result(normalized_target)
            if analysis_result:
                response_data['status']['analysis_data'] = analysis_result.to_dict()
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'})
        
        config = get_default_config()
        config.output_dir = OUTPUT_DIR
        config.wayback.enabled = data.get('wayback', True)
        config.urlscan.enabled = data.get('urlscan', True)
        config.alienvault.enabled = data.get('alienvault', True)
        config.js_analysis = data.get('analyze_js', True)
        
        engine = ReconEngine(config)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(engine.run(target, analyze_js=config.js_analysis))
        finally:
            loop.close()
        
        html_path = engine.export_html(target, OUTPUT_DIR)
        json_dir = engine.export_json(target, OUTPUT_DIR)
        
        report_folder = os.path.basename(os.path.dirname(html_path))
        
        results = engine.get_display_results()
        
        return jsonify({
            'success': True,
            'report_folder': report_folder,
            'html_path': html_path,
            'json_dir': json_dir,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/report/<path:folder>/<path:filename>')
def serve_report(folder, filename):
    report_path = os.path.join(OUTPUT_DIR, folder)
    return send_from_directory(report_path, filename)


def get_existing_reports():
    reports = []
    
    if not os.path.exists(OUTPUT_DIR):
        return reports
    
    for folder in os.listdir(OUTPUT_DIR):
        folder_path = os.path.join(OUTPUT_DIR, folder)
        
        if not os.path.isdir(folder_path):
            continue
        
        html_report = os.path.join(folder_path, 'report.html')
        if not os.path.exists(html_report):
            continue
        
        parts = folder.rsplit('_', 2)
        if len(parts) >= 3:
            domain = parts[0]
            date_str = f"{parts[1]}_{parts[2]}"
            try:
                date = datetime.strptime(date_str, '%Y%m%d_%H%M%S')
                date_formatted = date.strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_formatted = date_str
        else:
            domain = folder
            date_formatted = 'Unknown'
        
        reports.append({
            'folder': folder,
            'domain': domain,
            'date': date_formatted
        })
    
    reports.sort(key=lambda x: x['date'], reverse=True)
    
    return reports


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6789, debug=True)
