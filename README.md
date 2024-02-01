-------------------------------------Network Monitoring ReadMe------------------------------------------
- This project is run by starting "python answer.py" in powershell or cmd.

- To choose a service to add pick a number from 1-7. Choice #8 will use a echo client server to see if the local echo server is running.

- After adding all the necesary services to monitor, picking choice #9 will start the monitoring process. When choosing choice 9 and prompt will appear to the user before monitoring begins specifing interval frequency.

- When the programing is monitoring, pressing the 'esc' key at any point will exit the monitoring portion of the program and return the user to the "main" screen where they can add further services to monitor.

- Picking choice 10 will remove all added services. 

- To exit the program all together when in the "main" screen entering #11 will exit out the program. 

-------------------------------------------------------------------------------------------------------
-------------------------------------Echo Client/Server ReadMe-----------------------------------------
- To start the echo server, run "python echoServer" 
- To start the echo client, run "python echoClient"

- Run echoServer first and then echoClient. When running the echoClient it will send a message to the echo server and recieve a response back. 

- The echoServer is exited through a keyboard interrupt or if it receives a "goodbye" message from the client. 

- Currently, echoClient will send the message goodbye when directly run. 