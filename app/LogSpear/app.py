from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import Runnable, RunnableConfig
from typing import cast
from dotenv import load_dotenv
import os
import json
import chainlit as cl
import plotly.graph_objects as go
from collections import defaultdict

# Load environment variables from .env file
load_dotenv()


def parse_log_file(file_content: str) -> dict:
    """Parse uploaded JSON log file and extract key information"""
    try:
        logs = json.loads(file_content)

        # Extract suspicious devices
        suspicious_devices = []
        normal_devices = []
        botnet_connections = defaultdict(list)

        for log in logs:
            device_info = {
                "device_id": log.get("device_id"),
                "device_type": log.get("device_type"),
                "ip_address": log.get("ip_address"),
                "manufacturer": log.get("manufacturer"),
                "destination_ip": log.get("destination_ip"),
                "destination_country": log.get("destination_country"),
                "botnet_name": log.get("botnet_name"),
                "suspicious_activity": log.get("suspicious_activity"),
                "connected_devices": log.get("connected_devices", []),
                "activity_description": log.get("activity_description"),
                "traffic_volume_mb": log.get("traffic_volume_mb"),
                "failed_logins": log.get("failed_logins"),
            }

            if log.get("suspicious_activity"):
                suspicious_devices.append(device_info)
                # Track botnet connections
                if log.get("connected_devices"):
                    botnet_connections[log.get("ip_address")] = log.get(
                        "connected_devices"
                    )
            else:
                normal_devices.append(device_info)

        return {
            "suspicious_devices": suspicious_devices,
            "normal_devices": normal_devices,
            "botnet_connections": dict(botnet_connections),
            "total_devices": len(logs),
            "suspicious_count": len(suspicious_devices),
            "normal_count": len(normal_devices),
        }
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON format: {str(e)}"}
    except Exception as e:
        return {"error": f"Error parsing log file: {str(e)}"}


def create_botnet_graph(
    botnet_connections: dict, suspicious_devices: list
) -> go.Figure:
    """Create a network graph visualization of botnet connections"""

    # Build node and edge lists
    nodes = set()
    edges = []

    # Create a mapping of IP to device info
    device_map = {dev["ip_address"]: dev for dev in suspicious_devices}

    for source_ip, connected_ips in botnet_connections.items():
        nodes.add(source_ip)
        for target_ip in connected_ips:
            nodes.add(target_ip)
            edges.append((source_ip, target_ip))

    # Create node positions (simple circular layout)
    node_list = list(nodes)
    n = len(node_list)
    import math

    node_positions = {}
    for i, node in enumerate(node_list):
        angle = 2 * math.pi * i / n
        node_positions[node] = (math.cos(angle), math.sin(angle))

    # Create edge traces
    edge_x = []
    edge_y = []
    for source, target in edges:
        x0, y0 = node_positions[source]
        x1, y1 = node_positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1, color="#888"),
        hoverinfo="none",
        mode="lines",
    )

    # Create node traces
    node_x = []
    node_y = []
    node_text = []
    node_color = []

    for node in node_list:
        x, y = node_positions[node]
        node_x.append(x)
        node_y.append(y)

        if node in device_map:
            dev = device_map[node]
            text = f"{dev['device_type']}<br>IP: {node}<br>Botnet: {dev['botnet_name']}<br>Country: {dev['destination_country']}"
            node_text.append(text)
            # Color by botnet
            if dev["botnet_name"] == "Mirai_Variant_A":
                node_color.append("#ff0000")
            elif dev["botnet_name"] == "QBot_Network":
                node_color.append("#ff8800")
            elif dev["botnet_name"] == "Bashlite":
                node_color.append("#ffff00")
            elif dev["botnet_name"] == "PrinterBot":
                node_color.append("#00ff00")
            elif dev["botnet_name"] == "Hajime":
                node_color.append("#0088ff")
            else:
                node_color.append("#888888")
        else:
            node_text.append(f"IP: {node}")
            node_color.append("#cccccc")

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=[ip.split(".")[-1] for ip in node_list],  # Show last octet
        textposition="top center",
        hovertext=node_text,
        marker=dict(showscale=False, color=node_color, size=20, line_width=2),
    )

    # Create figure
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title="Botnet Device Connections",
            title_font_size=16,
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        ),
    )

    return fig


def format_analysis_report(parsed_data: dict) -> str:
    """Format the analysis report for LLM processing"""
    if "error" in parsed_data:
        return f"Error: {parsed_data['error']}"

    report = f"""
# IoT Security Log Analysis Report

## Overview
- **Total Devices Analyzed**: {parsed_data['total_devices']}
- **Suspicious Devices**: {parsed_data['suspicious_count']}
- **Normal Devices**: {parsed_data['normal_count']}

## Suspicious Devices Details

"""

    # Group by botnet
    botnets = defaultdict(list)
    countries = defaultdict(int)

    for device in parsed_data["suspicious_devices"]:
        if device["botnet_name"]:
            botnets[device["botnet_name"]].append(device)
        if device["destination_country"]:
            countries[device["destination_country"]] += 1

    # Add botnet breakdown
    report += "### Botnet Breakdown\n\n"
    for botnet, devices in botnets.items():
        report += f"**{botnet}**: {len(devices)} devices compromised\n\n"
        for dev in devices[:3]:  # Show first 3 of each botnet
            report += f"- **{dev['device_type']}** ({dev['ip_address']})\n"
            report += f"  - Manufacturer: {dev['manufacturer']}\n"
            report += f"  - Destination: {dev['destination_ip']} ({dev['destination_country']})\n"
            report += f"  - Failed Logins: {dev['failed_logins']}\n"
            report += f"  - Traffic: {dev['traffic_volume_mb']} MB\n"
            report += f"  - Activity: {dev['activity_description']}\n\n"

        if len(devices) > 3:
            report += f"  ... and {len(devices) - 3} more devices\n\n"

    # Add geographic analysis
    report += "### Geographic Threat Analysis\n\n"
    for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True):
        report += f"- **{country}**: {count} connections\n"

    return report


@cl.on_chat_start
async def on_chat_start():
    """Initialize the chatbot"""
    model = ChatOpenAI(streaming=True, model="gpt-4")
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You are an expert IoT security analyst specializing in botnet detection and incident response. 
                Your role is to analyze IoT device logs, identify security threats, and provide actionable insights.
                
                When analyzing logs, focus on:
                1. Identifying compromised devices and their indicators
                2. Mapping botnet infrastructure and C2 communications
                3. Assessing the severity and impact of threats
                4. Providing clear, actionable recommendations
                
                Be technical but clear in your explanations. Prioritize critical threats.""",
            ),
            ("human", "{question}"),
        ]
    )
    runnable = prompt | model | StrOutputParser()
    cl.user_session.set("runnable", runnable)

    # Send welcome message
    welcome_msg = """# 🛡️ LogSpear - IoT Security Incident Analyzer

Welcome! I'm your IoT security analyst. Upload a JSON log file to analyze IoT device activity and identify security threats.

**What I can do:**
- 🔍 Identify suspicious IP addresses and compromised devices
- 🌐 Track botnet origins and C2 server locations
- 📊 Visualize botnet device connections
- 🚨 Provide incident summaries and recommendations

**To get started:** Upload your IoT log file (JSON format) using the attachment button below."""

    await cl.Message(content=welcome_msg).send()


@cl.on_message
async def on_message(message: cl.Message):
    """Handle incoming messages and file uploads"""
    runnable = cast(Runnable, cl.user_session.get("runnable"))

    # Check if files were uploaded
    if message.elements:
        for element in message.elements:
            if element.type == "file":
                # Read the uploaded file
                try:
                    with open(element.path, "r") as f:
                        file_content = f.read()

                    # Parse the log file
                    parsed_data = parse_log_file(file_content)

                    if "error" in parsed_data:
                        await cl.Message(content=f"❌ {parsed_data['error']}").send()
                        return

                    # Store parsed data in session
                    cl.user_session.set("parsed_data", parsed_data)

                    # Create and send visualization
                    if parsed_data["suspicious_count"] > 0:
                        fig = create_botnet_graph(
                            parsed_data["botnet_connections"],
                            parsed_data["suspicious_devices"],
                        )

                        # Send the graph
                        await cl.Message(
                            content="## 📊 Botnet Network Visualization",
                            elements=[
                                cl.Plotly(
                                    name="botnet_graph", figure=fig, display="inline"
                                )
                            ],
                        ).send()

                    # Generate analysis report
                    analysis_report = format_analysis_report(parsed_data)

                    # Send to LLM for intelligent analysis
                    msg = cl.Message(content="")

                    analysis_prompt = f"""Analyze this IoT security log data and provide a comprehensive incident summary:

{analysis_report}

Please provide:
1. Executive Summary of the threats
2. Critical findings and most dangerous compromised devices
3. Botnet infrastructure analysis
4. Recommended immediate actions
5. Long-term security recommendations"""

                    async for chunk in runnable.astream(
                        {"question": analysis_prompt},
                        config=RunnableConfig(
                            callbacks=[cl.LangchainCallbackHandler()]
                        ),
                    ):
                        await msg.stream_token(chunk)

                    await msg.send()

                except Exception as e:
                    await cl.Message(
                        content=f"❌ Error processing file: {str(e)}"
                    ).send()

                return

    # Handle regular chat messages
    parsed_data = cl.user_session.get("parsed_data")

    if parsed_data:
        # If we have parsed data, include it in context
        analysis_report = format_analysis_report(parsed_data)
        enhanced_question = f"""Based on the previously analyzed IoT logs:

{analysis_report}

User Question: {message.content}"""
    else:
        enhanced_question = message.content

    msg = cl.Message(content="")

    async for chunk in runnable.astream(
        {"question": enhanced_question},
        config=RunnableConfig(callbacks=[cl.LangchainCallbackHandler()]),
    ):
        await msg.stream_token(chunk)

    await msg.send()
