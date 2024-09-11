import React, { useState, memo } from 'react';

// CopyButton Component for easy copying of code snippets
const CopyButton = memo(({ prompt }) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    try {
      navigator.clipboard.writeText(prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000); // Reset after 2 seconds
    } catch (err) {
      alert("Copy failed, please try manually.");
    }
  };

  return (
    <div>
      <button 
        onClick={copyToClipboard}
        style={{ padding: '5px', backgroundColor: '#007BFF', color: 'white', cursor: 'pointer', marginLeft: '10px' }}
        title="Copy SQL prompt to clipboard"
        aria-label="Copy SQL prompt to clipboard"
      >
        Copy
      </button>
      {copied && <span role="alert" aria-live="polite" style={{ color: 'green', marginLeft: '10px' }}>Copied!</span>}
    </div>
  );
});

// TableRow Component to render each row of the table
const TableRow = memo(({ concept, description, example, prompt }) => {
  const [editablePrompt, setEditablePrompt] = useState(prompt);

  return (
    <tr>
      <td>{concept}</td>
      <td>{description}</td>
      <td>
        <pre>{example}</pre>
        <CopyButton prompt={example} />
      </td>
      <td>
        <textarea 
          value={editablePrompt}
          onChange={(e) => setEditablePrompt(e.target.value)}
          rows="5" cols="50"
          style={{ fontFamily: 'monospace', padding: '5px', width: '100%' }}
          aria-label="Editable SQL prompt"
        />
        <CopyButton prompt={editablePrompt} />
      </td>
    </tr>
  );
});

// MainTable Component to render the entire table
const MainTable = () => {
  const tableData = [
    {
      concept: "Stored Procedures with IN",
      description: "IN parameters allow you to pass values to the stored procedure. These values are used inside the procedure but not returned to the caller.",
      example: "CREATE PROCEDURE GetCustomerOrders(IN customer_id INT) BEGIN SELECT * FROM orders WHERE customer_id = customer_id; END;",
      prompt: "Create a MySQL stored procedure that takes a customer ID as an IN parameter and retrieves all associated orders."
    },
    {
      concept: "Stored Procedures with OUT",
      description: "OUT parameters return values from a stored procedure back to the calling program. They are used when you want to return a calculated result.",
      example: "CREATE PROCEDURE GetOrderCount(IN customer_id INT, OUT total_orders INT) BEGIN SELECT COUNT(*) INTO total_orders FROM orders WHERE customer_id = customer_id; END;",
      prompt: "Create a MySQL stored procedure that takes a customer ID and returns the total number of orders as an OUT parameter."
    },
    {
      concept: "Stored Procedures with INOUT",
      description: "INOUT parameters accept input values and return output values, used for updating and returning the updated result.",
      example: "CREATE PROCEDURE UpdateAndReturnCredit(INOUT customer_credit DECIMAL(10,2)) BEGIN UPDATE customers SET credit_limit = credit_limit + 100 WHERE customer_id = 1; SET customer_credit = customer_credit + 100; END;",
      prompt: "Write a MySQL stored procedure that takes a customer's current credit as an INOUT parameter, adds $100 to it, and returns the updated value."
    },
    {
      concept: "Stored Functions",
      description: "Functions return a single value and are used in SQL statements to encapsulate reusable logic.",
      example: "CREATE FUNCTION GetCustomerLevel(points INT) RETURNS VARCHAR(20)...",
      prompt: "Create a MySQL function that calculates a customer's loyalty level (Silver, Gold, Platinum) based on their points."
    },
    {
      concept: "Triggers",
      description: "SQL code that automatically runs before or after a data-modification event (INSERT, UPDATE, DELETE). Ideal for automating business rules or logging.",
      example: "CREATE TRIGGER before_update_timestamp BEFORE UPDATE ON customers FOR EACH ROW SET NEW.modified = NOW();",
      prompt: "Create a MySQL trigger to automatically update the `modified` timestamp column before any record in the `customers` table is updated."
    },
    {
      concept: "Transactions",
      description: "Groups of SQL operations executed as a single unit of work. Transactions guarantee that either all operations complete or none do (ACID compliance).",
      example: "START TRANSACTION; UPDATE accounts SET balance = balance - 100 WHERE account_id = 1; UPDATE accounts SET balance = balance + 100 WHERE account_id = 2; COMMIT;",
      prompt: "Write a MySQL transaction to transfer $100 between two accounts, ensuring data integrity if an error occurs."
    }
  ];

  return (
    <div>
      <h2>MySQL Advanced Concepts Table</h2>
      <table border="1" cellPadding="10" cellSpacing="0" style={{ width: '100%', textAlign: 'left' }}>
        <thead>
          <tr>
            <th>Concept</th>
            <th>Description</th>
            <th>Best Practice Example</th>
            <th>Refined Prompt for Professionals</th>
          </tr>
        </thead>
        <tbody>
          {tableData.map((row, index) => (
            <TableRow
              key={index}
              concept={row.concept}
              description={row.description}
              example={row.example}
              prompt={row.prompt}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default MainTable;
