sequenceDiagram
    User1->>Client1: click "do something"
    Client1->>Server1: POST /doSomething
    Server1->>DB1: Store
    Server1->>Client1: Success
