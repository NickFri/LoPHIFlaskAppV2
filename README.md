# LoPHIFlaskApp

This software represents a dual-component system, designed to function both as a custom kiosk-like device and as a versatile control center. At its core lies a compact server computer, the Le Potato, which operates on the Ubuntu Server OS. This setup is augmented with desktop and graphics software, enabling the operation of a Google Chrome application in kiosk mode. The user-friendly interface is crucial for interaction with various connected devices.

The primary function of this system is to control external amplifiers, regulate temperature and fans, manage relays, and oversee LAN connections, thereby orchestrating their operations. This setup exemplifies a tailored solution for controlling switches and hardware necessary for a wide range of applications.

Integral to the system's operation are the bash scripts, used for executing specific tasks during startup within the Ubuntu Server environment. Additionally, the system leverages the creation of dedicated systemd services, ensuring continuous and efficient background operation of critical components like the web server. This dual approach of utilizing bash scripts for startup actions and services for ongoing processes ensures robust and seamless functionality from boot-up through regular operation.

Furthermore, this local Ubuntu web server communicates with a remotely hosted web server. This connection is pivotal for critical functions like user authentication and retrieval of configuration settings. Both the remote server and the local Ubuntu device server are programmed using Python Flask, with PyCharm as the development environment.

Overall, this system is an integration of hardware control, software programming, and network communication, culminating in a versatile and user-centric control device. It stands out for its seamless integration of local hardware control with remote server-based functionalities, offering a robust and adaptable solution for various practical applications.
