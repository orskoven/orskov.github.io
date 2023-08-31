const Skills = () => {
  const skillsCategories = {
    'Programming Languages': [
      '✨ JavaScript',
      '🐍 Python',
      '☕ JAVA',
      '📱 Swift (Programming Language)',
      'C',
      'Machine Code',
    ],
    Frameworks: [
      '🔮 React.js',
      '🌼 Spring Framework',
      '🌱 Spring Boot',
      '👢 Bootstrap',
      '🐍 Django',
      '🍶 Flask',
    ],
    'Database & Storage': ['🗃️ MySQL', '🔍 SQL', '📂 NoSQL'],
    'Machine Learning & Data Analysis': [
      '🤖 Tensorflow',
      '🧠 PyTorch',
      '📈 Data Analysis',
      '🐼 Pandas (Software)',
      '📊 Seaborn',
    ],
    'Web & Mobile Development': [
      '🎨 Cascading Style Sheets (CSS)',
      '🖥️ HTML5',
      '📱 iOS-udvikling',
      '💧 Agile & Waterfall Methodologies',
    ],
    'Other Skills': [
      '🔄 Agile Methodologies',
      '🎙️ Public Speaking',
      '⚡ Lambda Expressions',
      '🔐 Cybersikkerhed',
      '🗣️ Presentations',
      '✅ Unit Testing',
      '💨 Extreme Programming',
      '📐 GoF Patterns',
      '🧩 Object-Oriented Programming (OOP)',
      '🔍 Analytical Skills',
    ],
  };

  return (
    <section className="section">
      <h2>Skills</h2>
      {Object.keys(skillsCategories).map((category) => (
        <div className="category" key={category}>
          <h3>{category}</h3>
          <div className="skills-container">
            {skillsCategories[category].map((skill) => (
              <span className="skill" key={skill}>
                {skill}
              </span>
            ))}
          </div>
        </div>
      ))}
    </section>
  );
};

export default Skills;
  
