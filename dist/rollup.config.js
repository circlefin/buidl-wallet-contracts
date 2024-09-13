import typescript from 'rollup-plugin-typescript2';
import commonjs from 'rollup-plugin-commonjs';
 
export default {
  // input: './main.ts',
  plugins: [
    typescript({module: 'CommonJS'}),
    commonjs({
      extensions: ['.js', '.ts'],
    }) // the ".ts" extension is required
  ]
}
