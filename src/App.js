import React, { useState, useEffect } from 'react';
import Toolbar from './Toolbar';
import Posts from './Posts';

// Simulating a post component that could be dynamically generated based on props.
const Post = ({ Posts }) => (
  <div className="post">
    <h2>{post.title}</h2>
    <p>Date: {post.date} Author: {post.author} </p>
    <p>{post.content}</p>
    {link && <a href={link.href}>{link.text}</a>}
  </div>
);

const App = () => {
  const [posts, setPosts] = useState([]);

  useEffect(() => {
    // Simulate fetching JSON data from a local file or server
    fetch('/path/to/posts.json') // Adjust the path as needed
      .then(response => response.json())
      .then(data => setPosts(data))
      .catch(error => console.error('Error loading the posts:', error));
  }, []);

  return (
    <div className="container">
      <header className="header">
        <Toolbar />
        <p className="intro-text">
          Welcome to Binary Beans in technology and business.
        </p>
      </header>
      <main className="content">
        {posts.map((post, index) => (
          <Post key={index} {...post} />
        ))}
      </main>
    </div>
  );
};

export default App;