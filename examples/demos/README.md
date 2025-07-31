# Interactive Demos

This directory contains interactive demonstrations of specific framework features. These demos are designed to be educational and help users understand complex concepts through hands-on exploration.

## Demos Overview

### callback_system_demo.py
**Callback System Exploration**
- Interactive callback demonstration
- Real-time progress monitoring
- Response analysis examples
- Error handling patterns
- Campaign lifecycle management

**Features Demonstrated:**
- Progress tracking callbacks
- Response analysis functions
- Error handling callbacks
- Campaign start/end hooks
- Custom callback patterns

### pcap_fuzzing_demo.py
**PCAP Fuzzing Capabilities**
- Interactive PCAP file analysis
- Layer extraction demonstration
- Multiple fuzzing mode comparison
- Real-time packet processing
- Response correlation analysis

**Features Demonstrated:**
- PCAP file loading and analysis
- Layer-specific targeting
- Binary vs. field fuzzing
- Payload extraction techniques
- Interactive exploration tools

## Interactive Features

### Guided Exploration
Each demo provides:
- Step-by-step explanations
- Interactive prompts and choices
- Real-time output analysis
- Educational commentary
- Practical examples

### Safe Testing Environment
- No actual network traffic by default
- Simulated responses for demonstration
- Safe packet construction examples
- Educational mode with explanations

## Running the Demos

### Individual Demos
```bash
# Callback system exploration
python3 examples/demos/callback_system_demo.py

# PCAP fuzzing capabilities
python3 examples/demos/pcap_fuzzing_demo.py
```

### Interactive Mode
```bash
# Run with user interaction
python3 examples/demos/callback_system_demo.py --interactive

# Educational mode with extra explanations
python3 examples/demos/pcap_fuzzing_demo.py --educational
```

## Demo Structure

### Educational Flow
1. **Introduction**: Concept overview and goals
2. **Demonstration**: Live examples with explanations
3. **Interactive Elements**: User choices and exploration
4. **Summary**: Key takeaways and next steps

### Safe Execution
- Simulated network operations
- No actual packet transmission
- Safe target addresses (localhost)
- Educational-only examples

## Key Learning Objectives

### Callback System Demo
**Understanding Callbacks:**
- When callbacks are triggered
- How to design effective callbacks
- Common callback patterns
- Error handling in callbacks
- Performance considerations

**Practical Skills:**
- Writing custom callback functions
- Analyzing response patterns
- Implementing progress tracking
- Handling campaign lifecycle events

### PCAP Fuzzing Demo
**PCAP Analysis:**
- Loading and parsing PCAP files
- Understanding packet structure
- Layer extraction techniques
- Payload analysis methods

**Fuzzing Techniques:**
- Regression testing with PCAPs
- Field-based dictionary fuzzing
- Binary mutation strategies
- Combined fuzzing approaches

## Prerequisites

- Basic understanding of framework concepts
- Familiarity with network protocols
- Completion of basic examples (recommended)
- Python interactive experience

## Educational Value

### Hands-On Learning
- Interactive exploration of concepts
- Real-time feedback and analysis
- Step-by-step guidance
- Practical application examples

### Concept Visualization
- Visual representation of data flow
- Clear before/after comparisons
- Live demonstration of effects
- Interactive parameter adjustment

### Safe Experimentation
- No risk of network disruption
- Educational simulation mode
- Guided exploration paths
- Mistake-friendly environment

## Customization Options

### Demo Parameters
```python
# Adjust demo settings
DEMO_MODE = "educational"  # or "advanced"
SIMULATION_SPEED = "slow"  # or "normal", "fast"
DETAIL_LEVEL = "verbose"   # or "normal", "brief"
```

### Interactive Elements
- User choice points
- Parameter adjustment opportunities
- Exploration branches
- Custom scenario creation

## Common Use Cases

### Learning Framework Features
- Understanding callback architecture
- Exploring PCAP integration
- Comparing fuzzing modes
- Analyzing response patterns

### Teaching and Training
- Classroom demonstrations
- Workshop materials
- Self-paced learning
- Concept reinforcement

### Feature Evaluation
- Testing framework capabilities
- Comparing different approaches
- Evaluating performance characteristics
- Understanding limitations

## Extending the Demos

### Adding New Demos
```python
def new_feature_demo():
    """Template for new demo functions."""
    print("=== New Feature Demo ===")
    # Interactive elements
    # Educational content
    # Practical examples
    # Summary and next steps
```

### Customizing Existing Demos
- Modify parameters for different scenarios
- Add new callback examples
- Include additional PCAP files
- Extend interactive elements

## Best Practices

### Demo Design
- Clear learning objectives
- Progressive complexity
- Interactive engagement
- Safe execution environment

### User Experience
- Intuitive navigation
- Clear instructions
- Helpful error messages
- Educational value

### Code Quality
- Well-documented examples
- Error handling
- Clean, readable code
- Consistent style

## Troubleshooting

### Common Issues

#### Import Errors
Ensure you're running from the project root:
```bash
cd /path/to/scapy-fuzzer
python3 examples/demos/callback_system_demo.py
```

#### Missing PCAP Files
Some demos require sample PCAP files:
```bash
# Generate sample files if missing
python3 examples/utils/create_sample_pcaps.py
```

#### Permission Issues
Some demonstrations may require network permissions:
```bash
# Run with appropriate permissions if needed
sudo python3 examples/demos/pcap_fuzzing_demo.py
```

## Support and Feedback

### Getting Help
- Review demo source code
- Check example comments
- Consult framework documentation
- Ask questions in project issues

### Providing Feedback
- Report demo issues
- Suggest improvements
- Contribute new demos
- Share usage experiences

## Next Steps

After exploring the demos:

1. **Apply Concepts**: Use learned concepts in your own campaigns
2. **Advanced Examples**: Move to complex implementation examples
3. **Contribute**: Help improve demos and add new ones
4. **Teach Others**: Share knowledge and help other users

These interactive demos provide a safe, educational environment to explore advanced framework features and build confidence before implementing real fuzzing campaigns.
