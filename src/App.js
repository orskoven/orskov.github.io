import React from 'react';
import './App.css';
import Post from './Post';


const App = () => {
  return (
    <div className="container">
      <header className="header">
        <h1>Spilled Beans</h1>
        <p className="intro-text">
        </p>
      </header>
      <main className="content">
  <Post />
</main>
    </div>
  );
};

export default App;
