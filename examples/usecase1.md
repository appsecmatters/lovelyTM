sequenceDiagram
    Customer1->>MobileApp: Give n loyalty points to Customer2
    MobileApp->>Server: HTTP POST /givePoints(Customer2,n)
    Server->>DB: Update availablePoints for Customer1 and Customer2
    Server->>MobileApp: Send notification to Customer2
    MobileApp->>Customer2: Display n points given by Customer1
