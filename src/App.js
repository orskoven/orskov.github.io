import React from 'react';
import Toolbar from './Toolbar'; // Ensure Toolbar is imported if it's used for navigation or other UI elements.
import Post1 from './Post1';
import Post2 from './Post2';
import Post3 from './Post3';
import Post4 from './Post4';
import Post5 from './Post5';
import Post6 from './Post6';
import Post7 from './Post7';
import Post8 from './Post8';
import Post9 from './Post9';
import Post10 from './Post10';
import Post11 from './Post11';

// List of posts ordered by ID (assuming ID is chronological)
const posts = [
  { id: 11, component: <Post11 />, title: "Innovative Strategies in Tech Startups" },
  { id: 10, component: <Post10 />, title: "Evolving Trends in Renewable Energy" },
  { id: 9, component: <Post9 />, title: "Challenges and Opportunities in Quantum Computing" },
  { id: 8, component: <Post8 />, title: "The Rise of Smart Cities and IoT" },
  { id: 7, component: <Post7 />, title: "Breaking New Grounds in Blockchain Technology" },
  { id: 6, component: <Post6 />, title: "Exploring the Depths of Deep Learning in Modern AI" },
  { id: 5, component: <Post5 />, title: "Max Schrems: Prioritizing Enforcement and Innovation in Data Protection" },
  { id: 4, component: <Post4 />, title: "Navigating the Murky Waters of Cybersecurity Insurance" },
  { id: 3, component: <Post3 />, title: "Morten, Coach of the Cyber National Team" },
  { id: 2, component: <Post2 />, title: "Vestas: Advocating for Effective Cybersecurity Practices Amidst Rising Threats" },
  { id: 1, component: <Post1 />, title: "Advanced Cybersecurity Insights from the V2 Conference" },
];

const App = () => {
  return (
    <div className="App">
      <Toolbar />
      <div className="content">
        {posts.map(post => (
          <div key={post.id}>
            {post.component}
          </div>
        ))}
      </div>
    </div>
  );
};

export default App;